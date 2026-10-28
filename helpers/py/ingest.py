#!/usr/bin/env python3
"""recce-ingest: the single writer to the asset store.

Reads a JSON-lines record stream on stdin (already normalized and scope-gated)
and upserts it into Postgres. This is the ONLY component that issues SQL --
bash modules never touch the database, they only emit records.

Two record shapes:

  asset:
    {"kind":"asset","type":"subdomain","value":"a.example.com","attrs":{...}}

  finding (Dossier-shaped):
    {"kind":"finding","title":"...","severity":"high","cvss_score":7.5,
     "cvss_vector":"...","cwe":"CWE-79","description":"...",
     "evidence":[...],"remediation":"...","references":[...],
     "asset_ref":{"type":"url","value":"https://a.example.com/x"},
     "dedup_key":"optional-stable-key"}

With --workdir, each in-scope asset is also appended to
<workdir>/<type>.jsonl so the orchestrator can feed it to dependent modules.
"""
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

import psycopg2
import psycopg2.extras


def stable_dedup_key(module: str, rec: dict) -> str:
    if rec.get("dedup_key"):
        return str(rec["dedup_key"])
    ref = rec.get("asset_ref") or {}
    basis = "|".join([
        module or "",
        (rec.get("title") or "").strip().lower(),
        rec.get("cwe") or "",
        str(ref.get("type") or ""),
        str(ref.get("value") or ""),
    ])
    key = "auto:" + hashlib.sha1(basis.encode("utf-8")).hexdigest()
    return key


def _cap_dedup(dedup):
    """Keep dedup keys short. A key built from a 160KB URL is huge and wasteful;
    the md5 index would index it, but we hash long keys to keep the column lean
    while preserving uniqueness."""
    if dedup and len(dedup.encode("utf-8", "replace")) > 512:
        return "h:" + hashlib.sha1(dedup.encode("utf-8", "replace")).hexdigest()
    return dedup


# Values longer than this are almost always junk (data: URIs, embedded blobs
# katana/bbot pull out of pages), not useful recon assets — skip them rather
# than bloat the store. Overridable, but well above any real URL length.
MAX_VALUE_BYTES = int(os.environ.get("RECCE_MAX_VALUE", "32768"))


def _too_long(s):
    return s is not None and len(s.encode("utf-8", "replace")) > MAX_VALUE_BYTES


def upsert_asset(cur, engagement, run_id, module, rec):
    t = rec.get("type")
    v = rec.get("value")
    if not t or not v:
        return None
    if _too_long(v):
        # oversized value: skip (caller counts it). md5 dedup could index it,
        # but a 160KB "URL" is noise we don't want in the inventory.
        return None
    attrs = rec.get("attrs") or {}
    cur.execute(
        """
        INSERT INTO assets
            (engagement_id, type, value, attrs, source_module,
             first_run_id, last_run_id, first_seen, last_seen)
        VALUES (%s,%s,%s,%s,%s,%s,%s, now(), now())
        ON CONFLICT (engagement_id, type, md5(value)) DO UPDATE
            SET last_seen     = now(),
                last_run_id   = EXCLUDED.last_run_id,
                source_module = COALESCE(assets.source_module, EXCLUDED.source_module),
                attrs         = assets.attrs || EXCLUDED.attrs
        RETURNING id
        """,
        (engagement, t, v, psycopg2.extras.Json(attrs), module, run_id, run_id),
    )
    row = cur.fetchone()
    return row[0] if row else None


def resolve_asset_id(cur, engagement, ref):
    if not ref:
        return None
    cur.execute(
        "SELECT id FROM assets WHERE engagement_id=%s AND type=%s AND value=%s",
        (engagement, ref.get("type"), ref.get("value")),
    )
    row = cur.fetchone()
    return row[0] if row else None


def upsert_finding(cur, engagement, run_id, module, rec):
    dedup = _cap_dedup(stable_dedup_key(module, rec))
    asset_id = resolve_asset_id(cur, engagement, rec.get("asset_ref"))
    cur.execute(
        """
        INSERT INTO findings
            (engagement_id, run_id, asset_id, title, severity, cvss_score,
             cvss_vector, cwe, description, evidence, remediation, refs,
             source_module, dedup_key)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (engagement_id, md5(dedup_key)) DO UPDATE
            SET run_id      = EXCLUDED.run_id,
                asset_id    = COALESCE(findings.asset_id, EXCLUDED.asset_id),
                severity    = EXCLUDED.severity,
                cvss_score  = EXCLUDED.cvss_score,
                evidence    = EXCLUDED.evidence,
                updated_at  = now()
        """,
        (
            engagement, run_id, asset_id,
            rec.get("title") or "(untitled)",
            rec.get("severity") or "info",
            rec.get("cvss_score"),
            rec.get("cvss_vector"),
            rec.get("cwe"),
            rec.get("description"),
            psycopg2.extras.Json(rec.get("evidence") or []),
            rec.get("remediation"),
            psycopg2.extras.Json(rec.get("references") or []),
            module,
            dedup,
        ),
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=os.environ.get("DATABASE_URL"))
    ap.add_argument("--engagement", required=True)
    ap.add_argument("--run", required=True)
    ap.add_argument("--module", required=True)
    ap.add_argument("--workdir", default=None,
                    help="if set, append in-scope assets to <workdir>/<type>.jsonl")
    ap.add_argument("--commit-every", type=int,
                    default=int(os.environ.get("RECCE_COMMIT_EVERY", "100")),
                    help="commit (and flush working files) every N records so a long "
                         "streaming module persists progress and survives a timeout/kill")
    args = ap.parse_args()

    if not args.db:
        sys.exit("recce-ingest: DATABASE_URL not set (use --db or env)")

    workfiles = {}
    if args.workdir:
        Path(args.workdir).mkdir(parents=True, exist_ok=True)

    conn = psycopg2.connect(args.db)
    conn.autocommit = False
    n_assets = n_findings = n_bad = 0
    since_commit = 0
    every = max(1, args.commit_every)

    def checkpoint():
        """Persist progress so far: commit the txn and flush working files."""
        conn.commit()
        for fh in workfiles.values():
            fh.flush()

    try:
        # One cursor per committed batch; psycopg2 keeps the cursor usable across
        # commits, but we read stdin incrementally so records land as produced.
        with conn.cursor() as cur:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    n_bad += 1
                    continue
                kind = rec.get("kind")
                # Isolate each record in a savepoint so one unexpected DB error
                # (an oversized/odd row) skips just that record instead of
                # aborting the whole module and losing the batch.
                cur.execute("SAVEPOINT rec")
                try:
                    if kind == "asset":
                        if upsert_asset(cur, args.engagement, args.run, args.module, rec):
                            n_assets += 1
                            if args.workdir:
                                t = rec.get("type", "unknown")
                                fh = workfiles.get(t)
                                if fh is None:
                                    fh = open(os.path.join(args.workdir, f"{t}.jsonl"), "a")
                                    workfiles[t] = fh
                                fh.write(json.dumps(rec) + "\n")
                        else:
                            cur.execute("RELEASE SAVEPOINT rec")
                            n_bad += 1
                            continue
                    elif kind == "finding":
                        upsert_finding(cur, args.engagement, args.run, args.module, rec)
                        n_findings += 1
                    else:
                        cur.execute("RELEASE SAVEPOINT rec")
                        n_bad += 1
                        continue
                    cur.execute("RELEASE SAVEPOINT rec")
                except psycopg2.Error as e:
                    cur.execute("ROLLBACK TO SAVEPOINT rec")
                    cur.execute("RELEASE SAVEPOINT rec")
                    n_bad += 1
                    sys.stderr.write(f"recce-ingest[{args.module}]: skipped a record ({e.pgcode})\n")
                    continue
                # incremental commit: progress is durable without waiting for EOF
                since_commit += 1
                if since_commit >= every:
                    checkpoint()
                    since_commit = 0
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        for fh in workfiles.values():
            fh.close()
        conn.close()

    sys.stderr.write(
        f"recce-ingest[{args.module}]: assets={n_assets} findings={n_findings} bad={n_bad}\n"
    )


if __name__ == "__main__":
    main()
