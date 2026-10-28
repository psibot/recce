#!/usr/bin/env bash
# httprobe -- find live HTTP(S) services and basic tech.
#   consumes: subdomain, domain
#   produces: url, tech
#
# Wraps httpx (ProjectDiscovery). Emits a url asset per live endpoint plus a
# tech asset per detected technology, carrying status/title in attrs.
set -euo pipefail
MODULE_NAME=httprobe
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

input="$(cat)"
hosts="$( { printf '%s\n' "$input" | read_values subdomain; printf '%s\n' "$input" | read_values domain; } | sort -u || true)"
if [[ -z "${hosts// }" ]]; then
  log "no input hosts"
  exit 0
fi

if ! have httpx; then
  log "httpx not installed -- skipping"
  exit 0
fi

# Surface httpx stderr to the run console and parse partial output on non-zero.
tmp="$(mktemp)"
if ! printf '%s\n' "$hosts" | httpx -silent -json -tech-detect -status-code -title >"$tmp" 2>&2; then
  log "httpx exited non-zero; parsing whatever it produced (errors shown above)"
fi

python3 -c "$(cat <<'PY'
import json, sys
def emit(o):
    print(json.dumps(o)); sys.stdout.flush()  # stream per record
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        h = json.loads(line)
    except json.JSONDecodeError:
        continue
    url = h.get("url")
    if not url:
        continue
    attrs = {"status": h.get("status_code"), "title": h.get("title")}
    ip = h.get("host") or (h.get("a") or [None])[0]
    if ip:
        attrs["ip"] = ip
    emit({"kind":"asset","type":"url","value":url,"attrs":attrs})
    for t in (h.get("tech") or []):
        emit({"kind":"asset","type":"tech","value":t,"attrs":{"on":url}})
PY
)" < "$tmp"
rm -f "$tmp"
