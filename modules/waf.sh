#!/usr/bin/env bash
# waf -- WAF/CDN detection (reNgine's WAF detection).
#   consumes: url
#   produces: waf
#
# Wraps wafw00f (pip install wafw00f). Emits a waf asset per host where a WAF
# is detected, carrying the product/vendor. Skips cleanly if wafw00f is absent.
set -euo pipefail
MODULE_NAME=waf
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

input="$(cat)"
urls="$(printf '%s\n' "$input" | read_values url || true)"
if [[ -z "${urls// }" ]]; then
  log "no input urls"
  exit 0
fi

if ! have wafw00f; then
  log "wafw00f not installed -- skipping (pip install wafw00f)"
  exit 0
fi

# One host per scheme://netloc; wafw00f takes targets as args.
bases="$(python3 -c "$(cat <<'PY'
import sys
from urllib.parse import urlsplit
seen=set()
for line in sys.stdin:
    u=line.strip()
    if not u: continue
    p=urlsplit(u)
    if not p.scheme or not p.netloc: continue
    b=f"{p.scheme}://{p.netloc}"
    if b not in seen:
        seen.add(b); print(b)
PY
)" <<<"$urls")"

[[ -z "${bases// }" ]] && { log "no valid hosts"; exit 0; }

tmp="$(mktemp)"
# -f json -o <file> writes a JSON array of per-target results.
# shellcheck disable=SC2086
if ! wafw00f -f json -o "$tmp" $bases >&2 2>&2; then
  log "wafw00f non-zero (parsing partial output)"
fi

python3 -c "$(cat <<'PY'
import json, sys
path = sys.argv[1]
def emit(o):
    print(json.dumps(o)); sys.stdout.flush()  # stream per record
try:
    doc = json.load(open(path))
except Exception:
    sys.exit(0)
rows = doc if isinstance(doc, list) else [doc]
for r in rows:
    if not isinstance(r, dict):
        continue
    if not r.get("detected"):
        continue
    fw = r.get("firewall") or "Unknown"
    emit({"kind":"asset","type":"waf","value":fw,
          "attrs":{"url":r.get("url"),"manufacturer":r.get("manufacturer"),"via":"wafw00f"}})
PY
)" "$tmp"
rm -f "$tmp"
