#!/usr/bin/env bash
# wpscan -- WordPress vulnerability scan.
#   consumes: tech
#   produces: finding
#
# Runs WPScan only against hosts fingerprinted as WordPress (a `tech` asset
# whose value is WordPress, carrying the URL in attrs.on), so it never wastes
# time on non-WP sites. Maps WPScan's JSON vulnerabilities (core/plugin/theme)
# to findings, pulling CVE ids from references so the CVE-intel pass tiers them.
#
# Config (env):
#   WPSCAN_API_TOKEN  wpscan.com token (enables the vuln database; without it
#                     WPScan still enumerates but reports no known vulns)
#   WPSCAN_FLAGS      extra flags, e.g. "--enumerate vp,vt --random-user-agent"
set -euo pipefail
MODULE_NAME=wpscan
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

input="$(cat)"
# Extract URLs of WordPress hosts from tech assets.
targets="$(printf '%s\n' "$input" | python3 -c "$(cat <<'PY'
import json, sys
seen=set()
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    try: r=json.loads(line)
    except json.JSONDecodeError: continue
    if r.get("kind")!="asset" or r.get("type")!="tech": continue
    if "wordpress" not in (r.get("value") or "").lower(): continue
    url=(r.get("attrs") or {}).get("on")
    if url and url not in seen:
        seen.add(url); print(url)
PY
)")"

if [[ -z "${targets// }" ]]; then
  log "no WordPress hosts in input (needs a tech=WordPress asset)"
  exit 0
fi

if ! have wpscan; then
  log "wpscan not installed -- skipping"
  exit 0
fi

read -ra extra <<<"${WPSCAN_FLAGS:-}"
token_arg=(); [[ -n "${WPSCAN_API_TOKEN:-}" ]] && token_arg=(--api-token "$WPSCAN_API_TOKEN")

while IFS= read -r url; do
  [[ -z "$url" ]] && continue
  log "wpscan $url"
  tmp="$(mktemp)"
  wpscan --url "$url" --format json --no-banner "${token_arg[@]}" "${extra[@]}" \
      -o "$tmp" >&2 2>&2 || log "wpscan non-zero on $url (parsing partial output)"
  python3 -c "$(cat <<'PY'
import json, re, sys
def emit(o):
    print(json.dumps(o)); sys.stdout.flush()
url=sys.argv[1]; path=sys.argv[2]
CVE=re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
try: doc=json.load(open(path))
except Exception: sys.exit(0)

def vulns_from(section, kind):
    # section is a dict of name->info with a "vulnerabilities" list, or similar
    if not isinstance(section, dict): return
    for name, info in section.items():
        vs = (info or {}).get("vulnerabilities") if isinstance(info, dict) else None
        for v in (vs or []):
            yield name, v, kind

sections = [("version","core"), ("plugins","plugin"), ("themes","theme")]
for key, kind in sections:
    for name, v, k in vulns_from(doc.get(key, {}) if key!="version" else {"wordpress":doc.get("version",{})}, kind):
        title=v.get("title") or f"{k} {name} vulnerability"
        refs=v.get("references") or {}
        cve=None
        for c in (refs.get("cve") or []):
            cve=("CVE-"+c) if not str(c).upper().startswith("CVE-") else str(c).upper(); break
        if not cve:
            m=CVE.search(json.dumps(refs)); cve=m.group(0).upper() if m else None
        urls=refs.get("url") or []
        emit({"kind":"finding","title":f"WordPress {k}: {title}","severity":"high" if cve else "medium",
              "cwe":None,"description":f"WPScan flagged {k} '{name}' on {url}: {title}.",
              "evidence":[{"type":"text","label":"wpscan","content":f"{k} {name} @ {url}"}],
              "references":urls if isinstance(urls,list) else [str(urls)],
              "asset_ref":{"type":"url","value":url},
              **({"cve_id":cve} if cve else {}),
              "source_module":"wpscan",
              "dedup_key":f"wpscan:{cve or title}:{url}"})
PY
)" "$url" "$tmp"
  rm -f "$tmp"
done <<<"$targets"
