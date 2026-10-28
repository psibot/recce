#!/usr/bin/env bash
# gowitness -- headless screenshots of live URLs (alternative to Snapshot).
#   consumes: url
#   produces: screenshot, tech
#
# Wraps gowitness (SensePost). Screenshots land in GOWITNESS_DIR (mount it to
# keep them); each becomes a `screenshot` asset. gowitness needs Chrome/Chromium
# in the image. Skips cleanly if gowitness is absent.
#
# Config (env):
#   GOWITNESS_DIR    where screenshots are written (default /screenshots)
#   GOWITNESS_FLAGS  extra flags, e.g. "--timeout 15 --threads 4"
set -euo pipefail
MODULE_NAME=gowitness
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

input="$(cat)"
urls="$(printf '%s\n' "$input" | read_values url || true)"
if [[ -z "${urls// }" ]]; then
  log "no input urls"
  exit 0
fi

if ! have gowitness; then
  log "gowitness not installed -- skipping"
  exit 0
fi

outdir="${GOWITNESS_DIR:-/screenshots}"
mkdir -p "$outdir" 2>/dev/null || { log "cannot write $outdir -- skipping"; exit 0; }
read -ra extra <<<"${GOWITNESS_FLAGS:-}"

list="$(mktemp)"; printf '%s\n' "$urls" > "$list"
jsonl="$(mktemp)"
# gowitness v3: scan a file of URLs, write a JSONL report + screenshots.
if ! gowitness scan file -f "$list" --screenshot-path "$outdir" \
        --write-jsonl --write-jsonl-file "$jsonl" "${extra[@]}" >&2 2>&2; then
  log "gowitness exited non-zero; parsing whatever it produced"
fi

python3 -c "$(cat <<'PY'
import json, sys
def emit(o):
    print(json.dumps(o)); sys.stdout.flush()
path = sys.argv[1]
try:
    fh = open(path)
except OSError:
    sys.exit(0)
for line in fh:
    line = line.strip()
    if not line:
        continue
    try:
        r = json.loads(line)
    except json.JSONDecodeError:
        continue
    url = r.get("url") or r.get("final_url")
    if not url:
        continue
    shot = r.get("file_name") or r.get("filename") or r.get("screenshot")
    emit({"kind":"asset","type":"screenshot","value":shot or url,
          "attrs":{"source_url":url,"title":r.get("title"),
                   "status":r.get("response_code") or r.get("status_code"),"via":"gowitness"}})
    for t in (r.get("technologies") or r.get("tech") or []):
        name = t.get("value") if isinstance(t, dict) else t
        if name:
            emit({"kind":"asset","type":"tech","value":name,"attrs":{"on":url,"via":"gowitness"}})
PY
)" "$jsonl"
rm -f "$list" "$jsonl"
