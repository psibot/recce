#!/usr/bin/env bash
# portscan -- fast port scan via naabu.
#   consumes: subdomain, ip
#   produces: port, ip
#
# Emits a `port` asset per open port (value "host:port") and an `ip` asset per
# resolved address, so later modules can build on either.
#
# NOTE: naabu does a SYN scan when privileged and falls back to a connect scan
# otherwise. For SYN scanning in the container, give the worker CAP_NET_RAW
# (docker-compose: `cap_add: [NET_RAW]`); connect scan needs no capability.
set -euo pipefail
MODULE_NAME=portscan
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

input="$(cat)"
targets="$( { printf '%s\n' "$input" | read_values subdomain; printf '%s\n' "$input" | read_values ip; } | sort -u || true)"
if [[ -z "${targets// }" ]]; then
  log "no input hosts"
  exit 0
fi

if ! have naabu; then
  log "naabu not installed -- skipping"
  exit 0
fi

# Default to a CONNECT scan: it needs no raw-socket privileges, so it works in
# a stock container. Override with NAABU_SCAN_TYPE=s (SYN) if the worker has
# CAP_NET_RAW. naabu's own errors go to the run console (not /dev/null) so any
# real dependency problem is visible.
scan_type="${NAABU_SCAN_TYPE:-c}"
tmp="$(mktemp)"
if ! printf '%s\n' "$targets" | naabu -silent -json -s "$scan_type" >"$tmp" 2>&2; then
  log "naabu exited non-zero (scan-type=$scan_type); parsing whatever it produced"
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
        r = json.loads(line)
    except json.JSONDecodeError:
        continue
    ip = r.get("ip")
    port = r.get("port")
    host = r.get("host") or ip
    if port is None or host is None:
        continue
    emit({"kind":"asset","type":"port","value":f"{host}:{port}",
          "attrs":{"ip":ip,"port":port,"host":r.get("host"),"protocol":r.get("protocol")}})
    if ip:
        emit({"kind":"asset","type":"ip","value":ip,"attrs":{}})
PY
)" < "$tmp"
rm -f "$tmp"
