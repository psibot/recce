#!/usr/bin/env python3
"""recce enrich-cves — post-run CVE prioritization pass (CVEngine-style).

After an engine's modules finish, this reads the engagement's findings, pulls
any CVE id out of each (nuclei names its CVE templates `CVE-xxxx-xxxx`, and the
cvematch module sets cve_id directly), enriches them with CISA KEV + FIRST EPSS
via cve_intel, and writes back:

  * cve_id, kev, epss, priority  — the CVE-intel columns
  * severity                     — raised (never lowered) for KEV / fire tier
  * a "cve-intel" evidence block  — so the PDF/export show the reasoning

Only Python touches the DB, consistent with the rest of recce. The pass is
non-fatal: if the feeds are unreachable it enriches with whatever it has (often
just tiering from CVSS) and leaves the run successful.

Usage: enrich_cves.py --engagement <uuid> [--run <uuid>] [--db URL]
"""
import argparse
import json
import os
import re
import sys

import psycopg2
import psycopg2.extras

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cve_intel  # noqa: E402

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cve(row):
    """Find a CVE id in a finding, checking the most reliable fields first."""
    if row.get("cve_id"):
        return row["cve_id"].upper()
    for field in ("dedup_key", "title", "description"):
        v = row.get(field) or ""
        m = CVE_RE.search(v)
        if m:
            return m.group(0).upper()
    for ref in (row.get("refs") or []):
        m = CVE_RE.search(str(ref))
        if m:
            return m.group(0).upper()
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engagement", required=True)
    ap.add_argument("--run", default=None)
    ap.add_argument("--db", default=os.environ.get("DATABASE_URL"))
    args = ap.parse_args()
    if not args.db:
        sys.exit("enrich-cves: DATABASE_URL not set")

    def log(m):
        sys.stderr.write(m + "\n")

    conn = psycopg2.connect(args.db)
    conn.autocommit = False
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, title, description, severity, cvss_score, cwe, "
                "       dedup_key, cve_id, evidence, refs "
                "FROM findings WHERE engagement_id=%s",
                (args.engagement,),
            )
            rows = cur.fetchall()

        # Map each finding to its CVE id (if any).
        finding_cve = {}
        cvss_by_cve = {}
        for r in rows:
            cve = extract_cve(r)
            if not cve:
                continue
            finding_cve[r["id"]] = cve
            if r.get("cvss_score") is not None and cve not in cvss_by_cve:
                cvss_by_cve[cve] = float(r["cvss_score"])

        if not finding_cve:
            log("enrich-cves: no CVE-bearing findings; nothing to do")
            conn.commit()
            return

        intel = cve_intel.enrich(set(finding_cve.values()), cvss_by_cve, log=log)

        updated = 0
        with conn.cursor() as cur:
            for fid, cve in finding_cve.items():
                info = intel.get(cve, {"kev": False, "epss": None, "priority": "ice"})
                row = next(r for r in rows if r["id"] == fid)
                new_sev = cve_intel.severity_from(
                    info["kev"], info["priority"], row["severity"], row.get("cvss_score"))
                # add/refresh a cve-intel evidence block
                ev = row.get("evidence") or []
                ev = [b for b in ev if not (isinstance(b, dict) and b.get("type") == "cve-intel")]
                srcs = info.get("sources") or []
                ev.append({
                    "type": "cve-intel", "label": f"{cve} priority:{info['priority']}",
                    "content": (f"KEV={'yes' if info['kev'] else 'no'} "
                                f"exploit={'yes' if info.get('has_exploit') else 'no'} "
                                f"EPSS={info['epss'] if info['epss'] is not None else 'n/a'} "
                                f"tier={info['priority']}"
                                + (f" | sources: {', '.join(srcs)}" if srcs else "")),
                })
                cur.execute(
                    "UPDATE findings SET cve_id=%s, kev=%s, epss=%s, priority=%s, "
                    "severity=%s, evidence=%s, updated_at=now() WHERE id=%s",
                    (cve, info["kev"], info["epss"], info["priority"],
                     new_sev, psycopg2.extras.Json(ev), fid),
                )
                updated += 1
        conn.commit()
        kev_n = sum(1 for c in finding_cve.values() if intel.get(c, {}).get("kev"))
        fire_n = sum(1 for c in finding_cve.values() if intel.get(c, {}).get("priority") == "fire")
        log(f"enrich-cves: enriched {updated} findings "
            f"({len(set(finding_cve.values()))} unique CVEs, {kev_n} KEV, {fire_n} fire)")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
