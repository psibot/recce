#!/usr/bin/env python3
"""recce worker.

Pulls jobs off Redis and runs the bash orchestrator — the thin seam between
the Python web world and the bash core. As the orchestrator runs, every output
line is:
  * echoed to the worker log (docker logs),
  * appended to a capped Redis list  run:<id>:log     (replay on connect), and
  * published to a Redis channel      run:<id>:events  (live stream).

The web tier's websocket endpoint replays the list then follows the channel,
so the UI shows scans live the way reNgine does. Scale by running more workers.
"""
import os
import subprocess
import tempfile

from redis import Redis

RECCE_HOME = os.environ.get("RECCE_HOME", "/opt/recce")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")

LOG_CAP = 5000          # keep the last N lines for replay
LOG_TTL = 24 * 3600     # expire run logs after a day


def _publish(r, run_id, line):
    list_key = f"run:{run_id}:log"
    chan = f"run:{run_id}:events"
    pipe = r.pipeline()
    pipe.rpush(list_key, line)
    pipe.ltrim(list_key, -LOG_CAP, -1)
    pipe.expire(list_key, LOG_TTL)
    pipe.publish(chan, line)
    pipe.execute()


def run_scan(engagement_id: str, engine: str, run_id: str):
    """RQ entrypoint. Invokes the orchestrator for one run and streams output."""
    r = Redis.from_url(REDIS_URL)
    workdir = tempfile.mkdtemp(prefix="recce.")
    cmd = [
        os.path.join(RECCE_HOME, "orchestrator", "run-engine.sh"),
        "--engagement", engagement_id,
        "--engine", engine,
        "--run", run_id,
        "--workdir", workdir,
    ]
    env = dict(os.environ, RECCE_HOME=RECCE_HOME)

    _publish(r, run_id, f"[recce] starting engine={engine} run={run_id}")
    proc = subprocess.Popen(
        cmd, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    for line in proc.stdout:
        line = line.rstrip("\n")
        print(line, flush=True)
        _publish(r, run_id, line)
    proc.wait()
    _publish(r, run_id, f"[recce] engine finished rc={proc.returncode}")
    # sentinel so the UI knows the stream is complete and can close the socket
    r.publish(f"run:{run_id}:events", "[recce] __END__")

    if proc.returncode != 0:
        raise RuntimeError(f"orchestrator exited {proc.returncode} for run {run_id}")
    return {"run_id": run_id, "workdir": workdir}
