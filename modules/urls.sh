#!/usr/bin/env bash
# urls -- crawl live sites for endpoints (reNgine's endpoint discovery).
#   consumes: url
#   produces: url, endpoint
#
# Wraps katana (already in the image via pdtm). Each discovered endpoint is
# emitted as a url asset (so nuclei/fuzzing can consume it) and as an endpoint
# asset (the path-level record reNgine tracks). Headless crawling can be
# enabled with KATANA_FLAGS="-headless" if the worker has a browser.
set -euo pipefail
MODULE_NAME=urls
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

input="$(cat)"
urls="$(printf '%s\n' "$input" | read_values url || true)"
if [[ -z "${urls// }" ]]; then
  log "no input urls"
  exit 0
fi

if ! have katana; then
  log "katana not installed -- skipping"
  exit 0
fi

read -ra extra <<<"${KATANA_FLAGS:-}"
depth="${KATANA_DEPTH:-2}"

# katana reads seed URLs from stdin. -jsonl gives structured output; -silent
# keeps its own logs off stdout. Parse defensively: endpoint has lived under
# request.endpoint and (older) at top-level url.
printf '%s\n' "$urls" \
| katana -silent -jsonl -d "$depth" "${extra[@]}" 2>&2 \
| python3 -c "$(cat <<'PY'
import json, sys
from urllib.parse import urlsplit

def emit(o):
    print(json.dumps(o)); sys.stdout.flush()  # stream per record

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        r = json.loads(line)
    except json.JSONDecodeError:
        continue
    req = r.get("request") or {}
    url = req.get("endpoint") or r.get("endpoint") or r.get("url")
    if not url:
        continue
    resp = r.get("response") or {}
    status = resp.get("status_code") or r.get("status_code")
    emit({"kind":"asset","type":"url","value":url,
          "attrs":{"status":status,"via":"katana"}})
    # path-level endpoint record
    try:
        parts = urlsplit(url)
        path = parts.path or "/"
        emit({"kind":"asset","type":"endpoint","value":f"{parts.scheme}://{parts.netloc}{path}",
              "attrs":{"method":req.get("method"),"status":status,"via":"katana"}})
    except Exception:
        pass
PY
)"
