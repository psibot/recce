#!/usr/bin/env python3
"""recce exporter — turn an engagement's scan data into Dossier-importable output.

Two formats, one source of truth (the DB):

  dossier  — a single lossless JSON bundle: engagement, scope, assets, and
             findings with every Dossier-aligned field (severity, cvss, cwe,
             evidence blocks, remediation, references, status, asset link).
             This maps 1:1 onto Dossier's finding model.

  nuclei   — findings re-serialised as Nuclei JSONL, which Dossier already
             imports out of the box (one of its six scanner formats). This is
             the zero-adapter path: export, then import as Nuclei in Dossier.

Both are produced from `fetch_bundle`, so they never drift apart.
"""
import datetime
import decimal
import json

import psycopg2.extras

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _default(o):
    if isinstance(o, (datetime.datetime, datetime.date)):
        return o.isoformat()
    if isinstance(o, decimal.Decimal):
        return float(o)
    if isinstance(o, memoryview):
        return o.tobytes().decode("utf-8", "replace")
    return str(o)


def dumps(obj) -> str:
    return json.dumps(obj, default=_default, indent=2)


def fetch_bundle(conn, eid):
    """Assemble the full export bundle for an engagement, or None if missing."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id, name, slug, status, created_at FROM engagements WHERE id=%s", (eid,))
        eng = cur.fetchone()
        if not eng:
            return None

        cur.execute("SELECT kind, pattern_type, value FROM scope_rules "
                    "WHERE engagement_id=%s ORDER BY kind, value", (eid,))
        scope = cur.fetchall()

        cur.execute("SELECT type, value, attrs, source_module, first_seen, last_seen "
                    "FROM assets WHERE engagement_id=%s ORDER BY type, value", (eid,))
        assets = cur.fetchall()

        cur.execute(
            "SELECT f.title, f.severity, f.cvss_score, f.cvss_vector, f.cwe, f.description, "
            "       f.remediation, f.evidence, f.refs, f.status, f.source_module, f.dedup_key, "
            "       f.cve_id, f.kev, f.epss, f.priority, "
            "       a.type AS asset_type, a.value AS asset_value "
            "FROM findings f LEFT JOIN assets a ON a.id = f.asset_id "
            "WHERE f.engagement_id=%s "
            "ORDER BY array_position(ARRAY['fire','smoke','ice'], f.priority) NULLS LAST, "
            "         array_position(ARRAY['critical','high','medium','low','info'], f.severity), f.title",
            (eid,),
        )
        findings = cur.fetchall()

    # Build a hostname -> [IPs] map from the asset inventory so every export can
    # carry resolved IPs. IP hints live in several places: the resolve module
    # sets attrs.ips on the host; dnsx/httpx/nmap set attrs.ip on url/port/
    # service assets; and ip-type assets record attrs.host.
    host_ips = {}

    def _host_of(value):
        if not value:
            return None
        v = str(value)
        if "://" in v:
            v = v.split("://", 1)[1]
        v = v.split("/", 1)[0].split("?", 1)[0]
        if v.startswith("["):                       # [ipv6]:port
            return v[1:].split("]", 1)[0]
        return v.rsplit(":", 1)[0] if v.count(":") == 1 else v

    def _add(host, ip):
        if host and ip:
            host_ips.setdefault(host, [])
            if ip not in host_ips[host]:
                host_ips[host].append(ip)

    for a in assets:
        attrs = a.get("attrs") or {}
        atype, aval = a.get("type"), a.get("value")
        if atype == "ip" and attrs.get("host"):
            _add(attrs["host"], aval)
        host = _host_of(aval) if atype in ("subdomain", "url", "port", "service") else None
        for ip in (attrs.get("ips") or []):
            _add(host, ip)
        if attrs.get("ip"):
            _add(host, attrs["ip"])

    # attach resolved IPs to each asset (as an `ips` field) for the export
    assets_out = []
    for a in assets:
        a = dict(a)
        if a.get("type") == "ip":
            a["ips"] = [a["value"]]
        else:
            a["ips"] = host_ips.get(_host_of(a.get("value")), [])
        assets_out.append(a)

    # shape findings: fold the joined asset columns into a nested asset ref,
    # and attach the resolved IPs of the finding's host.
    shaped = []
    for f in findings:
        f = dict(f)
        atype = f.pop("asset_type", None)
        avalue = f.pop("asset_value", None)
        f["asset"] = {"type": atype, "value": avalue} if avalue else None
        f["references"] = f.pop("refs", []) or []
        f["ips"] = host_ips.get(_host_of(avalue), []) if avalue else []
        shaped.append(f)

    return {
        "recce_export_version": "1",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "engagement": dict(eng),
        "scope": [dict(s) for s in scope],
        "assets": assets_out,
        "findings": shaped,
        "host_ips": host_ips,
        "summary": {
            "asset_count": len(assets),
            "finding_count": len(shaped),
            "ip_count": sum(1 for a in assets if a.get("type") == "ip"),
            "resolved_host_count": len(host_ips),
            "by_severity": {s: sum(1 for f in shaped if f["severity"] == s) for s in SEV_ORDER},
            "by_priority": {p: sum(1 for f in shaped if f.get("priority") == p)
                            for p in ("fire", "smoke", "ice")},
            "kev_count": sum(1 for f in shaped if f.get("kev")),
        },
    }


def _finding_to_nuclei(f):
    """Map one recce finding onto a Nuclei result object Dossier can import."""
    evidence = f.get("evidence") or []
    ev0 = evidence[0] if evidence else {}
    dedup = f.get("dedup_key") or ""
    # recover the nuclei template id when the finding came from nuclei
    template = dedup.split(":")[1] if dedup.startswith("nuclei:") else (f.get("source_module") or "recce")
    cwe = [f["cwe"].lower()] if f.get("cwe") else []
    target = (f.get("asset") or {}).get("value") or ""
    cvss = f.get("cvss_score")
    return {
        "template-id": template,
        "info": {
            "name": f.get("title"),
            "severity": f.get("severity") or "info",
            "description": f.get("description"),
            "reference": f.get("references") or [],
            "remediation": f.get("remediation"),
            "classification": {
                "cwe-id": cwe,
                "cvss-score": float(cvss) if cvss is not None else None,
                "cvss-metrics": f.get("cvss_vector"),
            },
        },
        "matched-at": target,
        "host": target,
        "ip": (f.get("ips") or [None])[0],
        "ips": f.get("ips") or [],
        "matcher-name": (ev0.get("label") if isinstance(ev0, dict) else None),
        "request": ev0.get("request") if isinstance(ev0, dict) else None,
        "response": ev0.get("response") if isinstance(ev0, dict) else None,
    }


def to_nuclei_jsonl(bundle) -> str:
    lines = [json.dumps(_finding_to_nuclei(f), default=_default) for f in bundle["findings"]]
    return "\n".join(lines) + ("\n" if lines else "")


# --------------------------------------------------------------------------
# PDF findings report  (reportlab — pure Python, no system libs)
# --------------------------------------------------------------------------
SEV_COLORS = {
    "critical": "#b3123a", "high": "#c25a1d", "medium": "#9a7a12",
    "low": "#1f7a73", "info": "#5b6b82",
}


def to_pdf(bundle) -> bytes:
    """Render an engagement's findings as a PDF report, returned as bytes.

    A straightforward pentest findings report: title block, severity summary,
    then each finding (severity badge, title, CVSS/CWE/module/asset metadata,
    description, remediation, evidence, references) ordered most-severe first.
    """
    import io
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether,
    )

    def esc(s):
        s = "" if s is None else str(s)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    eng = bundle["engagement"]
    findings = bundle["findings"]
    summary = bundle["summary"]
    by_sev = summary["by_severity"]

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("recceTitle", parent=styles["Title"], fontSize=22,
                              textColor=colors.HexColor("#0f1420"), spaceAfter=2))
    styles.add(ParagraphStyle("recceSub", parent=styles["Normal"], fontSize=10,
                              textColor=colors.HexColor("#5b6b82"), spaceAfter=2))
    styles.add(ParagraphStyle("fTitle", parent=styles["Heading2"], fontSize=13,
                              spaceBefore=4, spaceAfter=2, textColor=colors.HexColor("#0f1420")))
    styles.add(ParagraphStyle("meta", parent=styles["Normal"], fontSize=8.5,
                              textColor=colors.HexColor("#5b6b82"), spaceAfter=4))
    styles.add(ParagraphStyle("label", parent=styles["Normal"], fontSize=8,
                              textColor=colors.HexColor("#8291a8"), spaceBefore=4,
                              spaceAfter=1, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle("body", parent=styles["Normal"], fontSize=9.5, leading=13,
                              alignment=TA_LEFT))
    styles.add(ParagraphStyle("evidence", parent=styles["Code"], fontSize=7.5, leading=9.5,
                              textColor=colors.HexColor("#2b3345"),
                              backColor=colors.HexColor("#f2f4f8"), borderPadding=4))

    story = []
    # --- title block ---
    story.append(Paragraph("recce — Findings Report", styles["recceTitle"]))
    story.append(Paragraph(f"{esc(eng['name'])} &nbsp;·&nbsp; {esc(eng['slug'])}", styles["recceSub"]))
    story.append(Paragraph(f"Status: {esc(eng.get('status'))} &nbsp;·&nbsp; "
                           f"Generated: {esc(bundle['generated_at'][:19].replace('T',' '))} UTC",
                           styles["recceSub"]))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#c9d2e0")))
    story.append(Spacer(1, 10))

    # --- severity summary table ---
    order = ["critical", "high", "medium", "low", "info"]
    header = [Paragraph("<b>Severity</b>", styles["body"])] + [
        Paragraph(f"<b>{s.title()}</b>", styles["body"]) for s in order]
    counts = [Paragraph("<b>Count</b>", styles["body"])] + [
        Paragraph(str(by_sev.get(s, 0)), styles["body"]) for s in order]
    tbl = Table([header, counts], colWidths=[26*mm] + [28*mm]*5)
    tstyle = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d2e0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f6")),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for i, s in enumerate(order, start=1):
        tstyle.append(("TEXTCOLOR", (i, 1), (i, 1), colors.HexColor(SEV_COLORS[s])))
        tstyle.append(("FONTNAME", (i, 1), (i, 1), "Helvetica-Bold"))
    tbl.setStyle(TableStyle(tstyle))
    story.append(tbl)
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"{summary['finding_count']} findings across "
                           f"{summary['asset_count']} assets.", styles["meta"]))
    # CVE prioritization summary (CVEngine-style), when present.
    bp = summary.get("by_priority") or {}
    if any(bp.values()) or summary.get("kev_count"):
        story.append(Paragraph(
            f"<b>CVE priority</b> &nbsp; "
            f"<font color='{SEV_COLORS['critical']}'>🔥 fire: {bp.get('fire',0)}</font> &nbsp;|&nbsp; "
            f"<font color='{SEV_COLORS['high']}'>smoke: {bp.get('smoke',0)}</font> &nbsp;|&nbsp; "
            f"ice: {bp.get('ice',0)} &nbsp;|&nbsp; "
            f"<b>{summary.get('kev_count',0)} on CISA KEV</b> (actively exploited)",
            styles["meta"]))
    story.append(Spacer(1, 10))

    if not findings:
        story.append(Paragraph("No findings recorded for this engagement.", styles["body"]))

    # --- one block per finding ---
    for idx, f in enumerate(findings, 1):
        sev = (f.get("severity") or "info").lower()
        sev_color = colors.HexColor(SEV_COLORS.get(sev, SEV_COLORS["info"]))
        block = []

        badge = Table([[Paragraph(f"<b>{sev.upper()}</b>",
                     ParagraphStyle("b", parent=styles["body"], textColor=colors.white, fontSize=8))]],
                     colWidths=[22*mm])
        badge.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), sev_color),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        title_tbl = Table([[badge, Paragraph(f"{idx}. {esc(f.get('title'))}", styles["fTitle"])]],
                          colWidths=[24*mm, 150*mm])
        title_tbl.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                       ("LEFTPADDING", (1, 0), (1, 0), 4)]))
        block.append(title_tbl)

        meta_bits = []
        if f.get("priority"):
            tier_label = {"fire": "🔥 FIRE", "smoke": "SMOKE", "ice": "ICE"}.get(f["priority"], f["priority"].upper())
            tier_color = {"fire": SEV_COLORS["critical"], "smoke": SEV_COLORS["high"],
                          "ice": SEV_COLORS["info"]}.get(f["priority"], SEV_COLORS["info"])
            meta_bits.append(f"<font color='{tier_color}'><b>{tier_label}</b></font>")
        if f.get("kev"):
            meta_bits.append(f"<font color='{SEV_COLORS['critical']}'><b>CISA KEV</b></font>")
        if f.get("cve_id"):
            meta_bits.append(esc(f["cve_id"]))
        if f.get("epss") is not None:
            meta_bits.append(f"EPSS {float(f['epss']):.3f}")
        if f.get("cvss_score") is not None:
            meta_bits.append(f"CVSS {esc(f['cvss_score'])}")
        if f.get("cwe"):
            meta_bits.append(esc(f["cwe"]))
        if f.get("source_module"):
            meta_bits.append(f"module: {esc(f['source_module'])}")
        if f.get("status"):
            meta_bits.append(f"status: {esc(f['status'])}")
        asset = f.get("asset") or {}
        if asset.get("value"):
            meta_bits.append(f"asset: {esc(asset['value'])}")
        if f.get("ips"):
            meta_bits.append(f"IP: {esc(', '.join(f['ips'][:4]))}")
        if meta_bits:
            block.append(Paragraph(" &nbsp;|&nbsp; ".join(meta_bits), styles["meta"]))

        if f.get("description"):
            block.append(Paragraph("Description", styles["label"]))
            block.append(Paragraph(esc(f["description"]), styles["body"]))
        if f.get("remediation"):
            block.append(Paragraph("Remediation", styles["label"]))
            block.append(Paragraph(esc(f["remediation"]), styles["body"]))

        ev = f.get("evidence") or []
        if ev and isinstance(ev[0], dict):
            content = ev[0].get("content") or ev[0].get("request") or ""
            if content:
                block.append(Paragraph("Evidence", styles["label"]))
                block.append(Paragraph(esc(str(content)[:1200]), styles["evidence"]))

        refs = f.get("references") or []
        if refs:
            block.append(Paragraph("References", styles["label"]))
            block.append(Paragraph("<br/>".join(esc(r) for r in refs[:8]), styles["meta"]))

        block.append(Spacer(1, 6))
        block.append(HRFlowable(width="100%", thickness=0.4, color=colors.HexColor("#dde3ec")))
        block.append(Spacer(1, 8))
        # keep a finding's header with at least its first lines together
        story.append(KeepTogether(block[:3]))
        story.extend(block[3:])

    buf = io.BytesIO()

    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#8291a8"))
        canvas.drawString(18*mm, 12*mm, f"recce findings report — {esc(eng['name'])}")
        canvas.drawRightString(A4[0]-18*mm, 12*mm, f"page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=16*mm, bottomMargin=18*mm,
                            title=f"recce findings — {eng['name']}")
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
