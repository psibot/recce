#!/usr/bin/env bash
# bbot -- BlackLantern Security BBOT recursive scanner.
#   consumes: domain
#   produces: subdomain, url, ip, port, tech, email, bucket, asn, finding
#
# BBOT is a recursive OSINT/recon engine. One run can enumerate subdomains,
# resolve IPs, find open ports, spider URLs, fingerprint tech, harvest emails,
# discover cloud buckets, and raise findings/vulnerabilities. This module runs
# BBOT, then maps its NDJSON event stream onto recce's typed records so every
# event flows through the same normalize -> scope -> ingest pipeline as any
# other module. Engines select which preset via the BBOT_PRESET env.
#
# Config (env):
#   BBOT_PRESET  space-separated preset(s). Default: subdomain-enum
#                e.g. "subdomain-enum", "subdomain-enum web", "cloud-enum"
#   BBOT_FLAGS   extra bbot flags, e.g. "-rf passive" for passive-only
#   BBOT_API_*   pass API keys via bbot's own -c, see docker-compose comments
set -euo pipefail
MODULE_NAME=bbot
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

input="$(cat)"
domains="$(printf '%s\n' "$input" | read_values domain || true)"
if [[ -z "${domains// }" ]]; then
  log "no input domains"
  exit 0
fi

if ! have bbot; then
  log "bbot not installed -- skipping (pip install bbot)"
  exit 0
fi

# Build -t target args and -p preset args as arrays (safe word-splitting).
targets=()
while IFS= read -r d; do [[ -n "$d" ]] && targets+=(-t "$d"); done <<<"$domains"
read -ra presets <<<"${BBOT_PRESET:-subdomain-enum}"
read -ra extra  <<<"${BBOT_FLAGS:-}"

outdir="$(mktemp -d)"
name="recce"
# -y auto-installs bbot's own tool dependencies on first run; --output/--name
# make the NDJSON file path deterministic. bbot's own logs go to the console.
if ! bbot "${targets[@]}" -p "${presets[@]}" "${extra[@]}" \
          -y --output "$outdir" --name "$name" >&2 2>&2; then
  log "bbot exited non-zero; parsing whatever it produced (errors above)"
fi

# Default output module writes newline-delimited JSON; filename has varied
# across versions (output.ndjson / output.json), so take whichever exists.
ndjson=""
for f in "$outdir/$name/output.ndjson" "$outdir/$name/output.json"; do
  [[ -s "$f" ]] && ndjson="$f" && break
done
if [[ -z "$ndjson" ]]; then
  log "no bbot NDJSON output found under $outdir/$name"
  exit 0
fi

python3 -c "$(cat <<'PY'
import json, sys

def emit(o):
    print(json.dumps(o)); sys.stdout.flush()  # stream per record

# BBOT severities already line up with recce's scale once lowercased.
SEV = {"INFO":"info","LOW":"low","MEDIUM":"medium","HIGH":"high","CRITICAL":"critical"}

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        continue

    etype = e.get("type")
    data = e.get("data")
    # Structured events carry a dict in data_json; string events in data.
    dj = e.get("data_json") if isinstance(e.get("data_json"), dict) else (data if isinstance(data, dict) else {})
    sval = data if isinstance(data, str) else None
    tags = e.get("tags") or []
    src = e.get("module") or "bbot"

    if etype == "DNS_NAME" and sval:
        emit({"kind":"asset","type":"subdomain","value":sval,"attrs":{"via":"bbot","module":src}})
    elif etype == "IP_ADDRESS" and sval:
        emit({"kind":"asset","type":"ip","value":sval,"attrs":{"via":"bbot"}})
    elif etype == "OPEN_TCP_PORT" and sval:
        host, _, port = sval.rpartition(":")
        emit({"kind":"asset","type":"port","value":sval,
              "attrs":{"host":host or None,"port":port or None,"via":"bbot"}})
    elif etype in ("URL","URL_UNVERIFIED") and sval:
        emit({"kind":"asset","type":"url","value":sval,
              "attrs":{"via":"bbot","unverified":etype=="URL_UNVERIFIED"}})
    elif etype == "TECHNOLOGY":
        tech = dj.get("technology") or sval
        if tech:
            emit({"kind":"asset","type":"tech","value":tech,
                  "attrs":{"on":dj.get("url") or dj.get("host"),"via":"bbot"}})
    elif etype == "EMAIL_ADDRESS" and sval:
        emit({"kind":"asset","type":"email","value":sval,"attrs":{"via":"bbot"}})
    elif etype == "STORAGE_BUCKET":
        val = dj.get("url") or dj.get("name") or sval
        if val:
            emit({"kind":"asset","type":"bucket","value":val,
                  "attrs":{"name":dj.get("name"),"via":"bbot"}})
    elif etype == "ASN":
        val = dj.get("asn") or sval
        if val:
            emit({"kind":"asset","type":"asn","value":str(val),"attrs":{"via":"bbot"}})
    elif etype in ("FINDING","VULNERABILITY"):
        desc = dj.get("description") or sval or etype
        host = dj.get("host") or ""
        url = dj.get("url") or host
        sev = SEV.get(str(dj.get("severity","")).upper(),
                      "info" if etype == "FINDING" else "medium")
        emit({
            "kind":"finding",
            "title": (desc[:117] + "...") if len(desc) > 120 else desc,
            "severity": sev,
            "description": desc,
            "evidence":[{"type":"text","label":f"bbot:{src}","content":json.dumps(dj)[:2000]}],
            "references": [],
            "asset_ref": {"type":"url","value":url} if url else None,
            "source_module":"bbot",
            "dedup_key": f"bbot:{etype}:{host}:{desc[:80]}",
        })
PY
)" < "$ndjson"
