#!/usr/bin/env python3
"""recce export: emit an engagement's results for Dossier.

Two formats:

  nuclei  Nuclei JSONL. Dossier already has a Nuclei importer, so this is the
          zero-friction path: recce's findings are reconstructed into nuclei's
          native record shape and Dossier ingests them with its existing
          importer. One JSON object per line.

  recce   A native recce JSON bundle: engagement + scope + summary + every
          finding (full Dossier-shaped fields and evidence) + the asset
          inventory. For archival, or a dedicated Dossier "recce" importer.

Importable both from the API (GET /engagements/<id>/export?format=...) and as a
CLI:  python3 export.py --engagement <uuid> --format nuclei
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import psycopg2
import psycopg2.extras


# --------------------------------------------------------------------------
# reads
# --------------------------------------------------------------------------
def get_engagement(conn, eid):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id, name, slug, status, created_at FROM engagements WHERE id=%s", (eid,))
        row = cur.fetchone()
    if not row:
        raise KeyError(f"no engagement {eid}")
    return row


def get_scope(conn, eid):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT kind, pattern_type, value FROM scope_rules WHERE engagement_id=%s ORDER BY kind, value", (eid,))
        return cur.fetchall()


def get_findings(conn, eid):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT f.title, f.severity, f.cvss_score, f.cvss_vector, f.cwe,
                   f.description, f.evidence, f.remediation, f.refs, f.status,
                   f.source_module, f.dedup_key, f.created_at, f.updated_at,
                   a.type AS asset_type, a.value AS asset_value
            FROM findings f
            LEFT JOIN assets a ON a.id = f.asset_id
            WHERE f.engagement_id = %s
            ORDER BY array_position(ARRAY['critical','high','medium','low','info'], f.severity),
                     f.updated_at DESC
            """,
            (eid,),
        )
        return cur.fetchall()


def get_assets(conn, eid):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT type, value, attrs, source_module, first_seen, last_seen "
            "FROM assets WHERE engagement_id=%s ORDER BY type, value",
            (eid,),
        )
        return cur.fetchall()


# --------------------------------------------------------------------------
# nuclei JSONL  (reconstruct nuclei records from recce findings)
# --------------------------------------------------------------------------
def _template_id(f):
    dk = f.get("dedup_key") or ""
    if dk.startswith("nuclei:"):
        parts = dk.split(":", 2)
        if len(parts) >= 2 and parts[1]:
            return parts[1]
    return f.get("source_module") or "recce"


def _first_evidence(f):
    ev = f.get("evidence") or []
    return ev[0] if ev else {}


def nuclei_record(f):
    ev = _first_evidence(f)
    matched = f.get("asset_value") or ev.get("content") or ""
    host = urlparse(matched).netloc or matched
    cvss = f.get("cvss_score")
    return {
        "template-id": _template_id(f),
        "info": {
            "name": f.get("title"),
            "severity": (f.get("severity") or "info"),
            "description": f.get("description"),
            "classification": {
                "cwe-id": [f["cwe"].lower()] if f.get("cwe") else [],
                "cvss-score": float(cvss) if cvss is not None else None,
                "cvss-metrics": f.get("cvss_vector"),
            },
            "reference": f.get("refs") or [],
        },
        "type": "http",
        "host": host,
        "matched-at": matched,
        "matcher-name": ev.get("label"),
        "request": ev.get("request"),
        "response": ev.get("response"),
        "timestamp": f["updated_at"].isoformat() if f.get("updated_at") else None,
    }


def nuclei_jsonl(conn, eid):
    return "\n".join(json.dumps(nuclei_record(f)) for f in get_findings(conn, eid))


# --------------------------------------------------------------------------
# native recce bundle
# --------------------------------------------------------------------------
def _json_default(o):
    if isinstance(o, datetime):
        return o.isoformat()
    return str(o)


def recce_bundle(conn, eid):
    eng = get_engagement(conn, eid)
    findings = get_findings(conn, eid)
    assets = get_assets(conn, eid)

    sev_counts, type_counts = {}, {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    for a in assets:
        type_counts[a["type"]] = type_counts.get(a["type"], 0) + 1

    return {
        "schema": "recce.export/v1",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "engagement": {k: eng[k] for k in ("id", "name", "slug", "status", "created_at")},
        "scope": get_scope(conn, eid),
        "summary": {
            "findings_by_severity": sev_counts,
            "assets_by_type": type_counts,
            "total_findings": len(findings),
            "total_assets": len(assets),
        },
        "findings": [
            {
                "title": f["title"], "severity": f["severity"],
                "cvss_score": float(f["cvss_score"]) if f["cvss_score"] is not None else None,
                "cvss_vector": f["cvss_vector"], "cwe": f["cwe"],
                "description": f["description"], "remediation": f["remediation"],
                "evidence": f["evidence"], "references": f["refs"],
                "status": f["status"], "source_module": f["source_module"],
                "asset": {"type": f["asset_type"], "value": f["asset_value"]}
                          if f["asset_value"] else None,
            }
            for f in findings
        ],
        "assets": [
            {"type": a["type"], "value": a["value"], "attrs": a["attrs"],
             "source_module": a["source_module"],
             "first_seen": a["first_seen"], "last_seen": a["last_seen"]}
            for a in assets
        ],
    }


def render(conn, eid, fmt):
    """Return (body_text, media_type, suffix) for the given format."""
    if fmt == "nuclei":
        return nuclei_jsonl(conn, eid), "application/x-ndjson", "nuclei.jsonl"
    if fmt == "recce":
        return (json.dumps(recce_bundle(conn, eid), indent=2, default=_json_default),
                "application/json", "recce.json")
    raise ValueError(f"unknown format {fmt!r} (use 'nuclei' or 'recce')")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engagement", required=True)
    ap.add_argument("--format", default="recce", choices=["nuclei", "recce"])
    ap.add_argument("--db", default=os.environ.get("DATABASE_URL"))
    args = ap.parse_args()
    if not args.db:
        sys.exit("export: DATABASE_URL not set (use --db or env)")
    conn = psycopg2.connect(args.db)
    try:
        body, _, _ = render(conn, args.engagement, args.format)
        print(body)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
