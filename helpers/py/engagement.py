#!/usr/bin/env python3
"""recce-engagement: DB-side lifecycle for a run, used by the orchestrator.

Keeps every SQL write in Python. Subcommands:

  prepare      --engagement E --workdir W
               Write W/scope.json (for recce-scope) and seed W/assets/domain.jsonl
               from the engagement's include=domain scope rules.

  create-run   --engagement E --engine NAME        -> prints new run UUID
  run-start    --run R
  run-finish   --run R --status done|failed
  module-start --run R --module M                  -> prints module_run UUID
  module-finish --module-run MR --status done|failed|skipped [--stats JSON]
"""
import argparse
import json
import os
import sys
from pathlib import Path

import psycopg2


def db():
    url = os.environ.get("DATABASE_URL")
    if not url:
        sys.exit("recce-engagement: DATABASE_URL not set")
    return psycopg2.connect(url)


def prepare(a):
    workdir = Path(a.workdir)
    (workdir / "assets").mkdir(parents=True, exist_ok=True)
    conn = db()
    with conn, conn.cursor() as cur:
        cur.execute(
            "SELECT kind, pattern_type, value FROM scope_rules WHERE engagement_id=%s",
            (a.engagement,),
        )
        rows = cur.fetchall()
    include, exclude = [], []
    seed_domains = []
    for kind, ptype, value in rows:
        (include if kind == "include" else exclude).append({"type": ptype, "value": value})
        if kind == "include" and ptype == "domain":
            seed_domains.append(value)

    (workdir / "scope.json").write_text(json.dumps({"include": include, "exclude": exclude}))

    seed_path = workdir / "assets" / "domain.jsonl"
    with seed_path.open("w") as fh:
        for d in sorted(set(seed_domains)):
            fh.write(json.dumps({"kind": "asset", "type": "domain", "value": d, "attrs": {"seed": True}}) + "\n")
    sys.stderr.write(f"recce-engagement: prepared {len(include)} include / {len(exclude)} exclude rules, "
                     f"{len(seed_domains)} seed domains\n")


def create_run(a):
    conn = db()
    with conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO runs (engagement_id, engine, status) VALUES (%s,%s,'queued') RETURNING id",
            (a.engagement, a.engine),
        )
        print(cur.fetchone()[0])


def run_start(a):
    conn = db()
    with conn, conn.cursor() as cur:
        cur.execute("UPDATE runs SET status='running', started_at=now() WHERE id=%s", (a.run,))


def run_finish(a):
    conn = db()
    with conn, conn.cursor() as cur:
        cur.execute("UPDATE runs SET status=%s, finished_at=now() WHERE id=%s", (a.status, a.run))


def module_start(a):
    conn = db()
    with conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO module_runs (run_id, module, status, started_at) "
            "VALUES (%s,%s,'running',now()) RETURNING id",
            (a.run, a.module),
        )
        print(cur.fetchone()[0])


def module_finish(a):
    stats = json.loads(a.stats) if a.stats else {}
    conn = db()
    with conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE module_runs SET status=%s, finished_at=now(), stats=%s WHERE id=%s",
            (a.status, json.dumps(stats), a.module_run),
        )


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("prepare"); p.add_argument("--engagement", required=True); p.add_argument("--workdir", required=True); p.set_defaults(fn=prepare)
    p = sub.add_parser("create-run"); p.add_argument("--engagement", required=True); p.add_argument("--engine", required=True); p.set_defaults(fn=create_run)
    p = sub.add_parser("run-start"); p.add_argument("--run", required=True); p.set_defaults(fn=run_start)
    p = sub.add_parser("run-finish"); p.add_argument("--run", required=True); p.add_argument("--status", required=True); p.set_defaults(fn=run_finish)
    p = sub.add_parser("module-start"); p.add_argument("--run", required=True); p.add_argument("--module", required=True); p.set_defaults(fn=module_start)
    p = sub.add_parser("module-finish"); p.add_argument("--module-run", required=True); p.add_argument("--status", required=True); p.add_argument("--stats", default=None); p.set_defaults(fn=module_finish)

    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
