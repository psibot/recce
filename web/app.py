#!/usr/bin/env python3
"""recce web/API tier.

The web tier NEVER runs tools. It manages engagements, scope and users, serves
the operator console, and *enqueues* scan jobs onto Redis. A recon scan lives
for hours; an HTTP request lives for seconds — so handlers drop a job on the
queue and return immediately. Workers do the work and stream output back
through Redis, which the websocket endpoint relays to the UI.
"""
import os
import re
import glob
import uuid

import psycopg2
import psycopg2.extras
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from redis import Redis
from rq import Queue

import exporter

DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
HERE = os.path.dirname(__file__)
ENGINES_DIR = os.environ.get("RECCE_ENGINES", os.path.join(HERE, "engines"))

app = FastAPI(title="recce", version="0.2.0")
queue = Queue("recce", connection=Redis.from_url(REDIS_URL))

if os.path.isdir(os.path.join(HERE, "static")):
    app.mount("/static", StaticFiles(directory=os.path.join(HERE, "static")), name="static")


def db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    return conn


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or uuid.uuid4().hex[:8]


class EngagementIn(BaseModel):
    name: str


class ScopeIn(BaseModel):
    kind: str            # include | exclude
    pattern_type: str    # domain | cidr | regex
    value: str


class ScanIn(BaseModel):
    engine: str = "default"


# --------------------------------------------------------------------------
# Engagements & scope
# --------------------------------------------------------------------------
@app.post("/engagements")
def create_engagement(body: EngagementIn):
    slug = slugify(body.name)
    with db() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "INSERT INTO engagements (name, slug) VALUES (%s,%s) RETURNING id, name, slug, status",
            (body.name, slug),
        )
        return cur.fetchone()


@app.get("/engagements")
def list_engagements():
    with db() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id, name, slug, status, created_at FROM engagements ORDER BY created_at DESC")
        return cur.fetchall()


@app.get("/engagements/{eid}")
def engagement_detail(eid: str):
    with db() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id, name, slug, status, created_at FROM engagements WHERE id=%s", (eid,))
        eng = cur.fetchone()
        if not eng:
            raise HTTPException(404, "no such engagement")
        cur.execute("SELECT id, kind, pattern_type, value FROM scope_rules WHERE engagement_id=%s ORDER BY kind, value", (eid,))
        eng["scope"] = cur.fetchall()
        cur.execute("SELECT type, count(*) AS n FROM assets WHERE engagement_id=%s GROUP BY type ORDER BY type", (eid,))
        eng["asset_counts"] = cur.fetchall()
        cur.execute("SELECT severity, count(*) AS n FROM findings WHERE engagement_id=%s GROUP BY severity", (eid,))
        eng["finding_counts"] = {r["severity"]: r["n"] for r in cur.fetchall()}
        return eng


@app.delete("/engagements/{eid}")
def delete_engagement(eid: str):
    """Delete an engagement and everything under it.

    scope_rules, runs, module_runs, assets and findings all reference the
    engagement with ON DELETE CASCADE, so one delete removes the whole tree.
    """
    with db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM engagements WHERE id=%s RETURNING id", (eid,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "no such engagement")
    return {"deleted": str(row[0])}


@app.post("/engagements/{eid}/scope")
def add_scope(eid: str, body: ScopeIn):
    if body.kind not in ("include", "exclude") or body.pattern_type not in ("domain", "cidr", "regex"):
        raise HTTPException(400, "invalid scope rule")
    with db() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "INSERT INTO scope_rules (engagement_id, kind, pattern_type, value) "
            "VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING id",
            (eid, body.kind, body.pattern_type, body.value),
        )
        row = cur.fetchone()
    return {"ok": True, "id": row["id"] if row else None}


# --------------------------------------------------------------------------
# Scans & runs
# --------------------------------------------------------------------------
@app.get("/engines")
def list_engines():
    names = sorted(os.path.splitext(os.path.basename(p))[0]
                   for p in glob.glob(os.path.join(ENGINES_DIR, "*.yml")))
    return {"engines": names or ["default"]}


@app.post("/engagements/{eid}/scans")
def start_scan(eid: str, body: ScanIn):
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO runs (engagement_id, engine, status) VALUES (%s,%s,'queued') RETURNING id",
            (eid, body.engine),
        )
        run_id = str(cur.fetchone()[0])
    queue.enqueue("worker.run_scan", eid, body.engine, run_id, job_timeout=6 * 3600)
    return {"run_id": run_id, "status": "queued"}


@app.get("/engagements/{eid}/runs")
def list_runs(eid: str):
    with db() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id, engine, status, started_at, finished_at, created_at "
                    "FROM runs WHERE engagement_id=%s ORDER BY created_at DESC LIMIT 50", (eid,))
        return cur.fetchall()


@app.get("/runs/{run_id}")
def get_run(run_id: str):
    with db() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM runs WHERE id=%s", (run_id,))
        run = cur.fetchone()
        if not run:
            raise HTTPException(404, "no such run")
        cur.execute("SELECT module, status, stats, started_at, finished_at "
                    "FROM module_runs WHERE run_id=%s ORDER BY started_at", (run_id,))
        run["modules"] = cur.fetchall()
        return run


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------
@app.get("/engagements/{eid}/assets")
def list_assets(eid: str, type: str | None = None):
    q = "SELECT type, value, attrs, source_module, first_seen, last_seen FROM assets WHERE engagement_id=%s"
    args = [eid]
    if type:
        q += " AND type=%s"
        args.append(type)
    q += " ORDER BY last_seen DESC LIMIT 2000"
    with db() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(q, args)
        return cur.fetchall()


@app.get("/engagements/{eid}/findings")
def list_findings(eid: str):
    with db() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT title, severity, cvss_score, cwe, status, source_module, updated_at, "
            "       cve_id, kev, epss, priority "
            "FROM findings WHERE engagement_id=%s "
            "ORDER BY array_position(ARRAY['fire','smoke','ice'], priority) NULLS LAST, "
            "         array_position(ARRAY['critical','high','medium','low','info'], severity), "
            "         updated_at DESC",
            (eid,),
        )
        return cur.fetchall()


@app.get("/engagements/{eid}/export")
def export_engagement(eid: str, format: str = "dossier"):
    """Export an engagement's scan data for import into Dossier.

    format=dossier -> lossless recce JSON bundle (maps to Dossier's model)
    format=nuclei  -> Nuclei JSONL, importable via Dossier's Nuclei importer
    format=pdf     -> a printable findings report
    """
    with db() as conn:
        bundle = exporter.fetch_bundle(conn, eid)
    if bundle is None:
        raise HTTPException(404, "no such engagement")
    slug = bundle["engagement"]["slug"]

    if format == "nuclei":
        body = exporter.to_nuclei_jsonl(bundle)
        return Response(
            body, media_type="application/x-ndjson",
            headers={"Content-Disposition": f'attachment; filename="{slug}-nuclei.jsonl"'},
        )
    if format == "pdf":
        pdf = exporter.to_pdf(bundle)
        return Response(
            pdf, media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{slug}-findings.pdf"'},
        )
    if format in ("dossier", "recce", "json"):
        body = exporter.dumps(bundle)
        return Response(
            body, media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{slug}-recce.json"'},
        )
    raise HTTPException(400, "unknown format (use dossier|nuclei|pdf)")


# --------------------------------------------------------------------------
# Live scan output: replay the capped log list, then follow the pub/sub channel
# --------------------------------------------------------------------------
@app.websocket("/ws/runs/{run_id}")
async def ws_run(websocket: WebSocket, run_id: str):
    await websocket.accept()
    r = aioredis.from_url(REDIS_URL)
    pubsub = None
    try:
        for line in await r.lrange(f"run:{run_id}:log", 0, -1):
            await websocket.send_text(line.decode() if isinstance(line, bytes) else line)
        pubsub = r.pubsub()
        await pubsub.subscribe(f"run:{run_id}:events")
        async for msg in pubsub.listen():
            if msg.get("type") != "message":
                continue
            data = msg["data"]
            text = data.decode() if isinstance(data, bytes) else data
            await websocket.send_text(text)
            if text.endswith("__END__"):
                break
    except WebSocketDisconnect:
        pass
    finally:
        if pubsub is not None:
            await pubsub.aclose()
        await r.aclose()


@app.get("/", response_class=HTMLResponse)
def index():
    path = os.path.join(HERE, "static", "index.html")
    if os.path.exists(path):
        with open(path) as fh:
            return fh.read()
    return "<h1>recce</h1><p>UI not found; see /docs for the API.</p>"
