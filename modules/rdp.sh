#!/usr/bin/env bash
# rdp -- RDP exposure + NLA check (aardwolf).
#   consumes: port
#   produces: finding
#
# For every open RDP port (3389) in the inventory, raises an exposure finding,
# and — when aardwolf is available — probes whether Network Level Authentication
# (NLA) is enforced. NLA disabled is a real, higher-severity finding (pre-auth
# attack surface, BlueKeep-class exposure).
#
# NOTE on fit: aardwolf is an interactive asyncio RDP/VNC client, not a batch
# findings scanner, so this module uses it for a focused NLA probe rather than
# a deep integration. It degrades to a plain exposure finding when aardwolf or
# its probe helper isn't available.
#
# Config (env):
#   RDP_PORTS       comma list of ports treated as RDP (default 3389)
#   AARDWOLF_PROBE  path to an NLA-probe helper that prints "NLA=on|off" for a
#                   given host:port (optional; without it, exposure-only)
set -euo pipefail
MODULE_NAME=rdp
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

input="$(cat)"
rdp_ports="${RDP_PORTS:-3389}"

# Collect host:port for ports matching the RDP set.
targets="$(printf '%s\n' "$input" | python3 -c "$(cat <<'PY'
import json, os, sys
want = set(p.strip() for p in os.environ.get("RDP_PORTS","3389").split(","))
seen=set()
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    try: r=json.loads(line)
    except json.JSONDecodeError: continue
    if r.get("kind")!="asset" or r.get("type")!="port": continue
    val=r.get("value") or ""           # host:port
    attrs=r.get("attrs") or {}
    port=str(attrs.get("port") or (val.rsplit(":",1)[1] if ":" in val else ""))
    if port in want and val and val not in seen:
        seen.add(val); print(val)
PY
)")"

if [[ -z "${targets// }" ]]; then
  log "no RDP ports ($rdp_ports) in input"
  exit 0
fi

probe="${AARDWOLF_PROBE:-}"
have_probe=0
if [[ -n "$probe" && -x "$probe" ]]; then have_probe=1
elif have aardwolf || python3 -c "import aardwolf" 2>/dev/null; then
  log "aardwolf present but no AARDWOLF_PROBE helper set -- exposure-only"
fi

while IFS= read -r hp; do
  [[ -z "$hp" ]] && continue
  nla="unknown"
  if [[ $have_probe -eq 1 ]]; then
    nla="$("$probe" "$hp" 2>/dev/null | sed -n 's/^NLA=//p' | head -1)"
    [[ -z "$nla" ]] && nla="unknown"
  fi
  if [[ "$nla" == "off" ]]; then
    sev="high"; title="RDP exposed without NLA: $hp"
    desc="RDP is reachable on $hp and Network Level Authentication is NOT enforced, exposing pre-auth attack surface (BlueKeep-class)."
  else
    sev="low"; title="RDP service exposed: $hp"
    desc="RDP is reachable on $hp (NLA: $nla). Exposed RDP is a common initial-access vector; restrict to VPN/allowlist."
  fi
  emit_finding "$(python3 -c "import json,sys; print(json.dumps({
    'title': sys.argv[1], 'severity': sys.argv[2], 'description': sys.argv[3],
    'evidence': [{'type':'text','label':'rdp','content': 'NLA='+sys.argv[4]}],
    'references': ['https://attack.mitre.org/techniques/T1021/001/'],
    'asset_ref': {'type':'port','value': sys.argv[5]},
    'source_module': 'rdp', 'dedup_key': 'rdp:'+sys.argv[5]}))" \
    "$title" "$sev" "$desc" "$nla" "$hp")"
done <<<"$targets"
