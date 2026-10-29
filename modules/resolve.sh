#!/usr/bin/env bash
# resolve -- resolve hostnames to IPs (DNS A/AAAA) via dnsx.
#   consumes: subdomain, domain
#   produces: ip, subdomain
#
# For every hostname, emits an `ip` asset per resolved address AND re-emits the
# hostname as a `subdomain` asset carrying attrs.ips, which ingest merges into
# the existing host record — so each host knows its IPs, and the IPs feed
# portscan/nmap and show up in exports. dnsx is already in the image (pdtm).
#
# Config (env):
#   RESOLVE_FLAGS   extra dnsx flags, e.g. "-r /resolvers.txt -t 200"
set -euo pipefail
MODULE_NAME=resolve
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

input="$(cat)"
hosts="$( { printf '%s\n' "$input" | read_values subdomain; printf '%s\n' "$input" | read_values domain; } | sort -u | grep -v '^$' || true)"
if [[ -z "${hosts// }" ]]; then
  log "no hostnames to resolve"
  exit 0
fi

if ! have dnsx; then
  log "dnsx not installed -- skipping"
  exit 0
fi

read -ra extra <<<"${RESOLVE_FLAGS:-}"
# -a/-aaaa: A and AAAA records; -json: structured; -resp: include answers.
printf '%s\n' "$hosts" \
| dnsx -silent -json -a -aaaa -resp "${extra[@]}" 2>&2 \
| python3 -c "$(cat <<'PY'
import json, sys
def emit(o):
    print(json.dumps(o)); sys.stdout.flush()
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        r = json.loads(line)
    except json.JSONDecodeError:
        continue
    host = r.get("host")
    ips = []
    for k in ("a", "aaaa"):
        v = r.get(k)
        if isinstance(v, list):
            ips.extend(v)
        elif isinstance(v, str):
            ips.append(v)
    ips = [ip for ip in dict.fromkeys(ips) if ip]   # de-dupe, keep order
    if not host or not ips:
        continue
    for ip in ips:
        emit({"kind":"asset","type":"ip","value":ip,
              "attrs":{"host":host,"via":"dnsx"}})
    # annotate the host with its IPs (ingest merges attrs)
    emit({"kind":"asset","type":"subdomain","value":host,
          "attrs":{"ips":ips,"via":"dnsx"}})
PY
)"
