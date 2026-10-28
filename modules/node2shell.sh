#!/usr/bin/env bash
# node2shell -- detect CVE-2026-111497 in Node.js HTTP apps (Assetnote scanner).
#   consumes: url
#   produces: finding
#
# Wraps assetnote/node2shell-scanner. It sends a large Brotli probe (no command
# execution) and reports vulnerable hosts as JSON. Vulnerable hits become a
# critical finding carrying cve_id CVE-2026-111497, so the CVE-intel pass tiers
# it. Skips cleanly if the scanner isn't installed.
#
# Config (env):
#   NODE2SHELL_BIN    how to invoke it (default: "python3 /opt/node2shell/scanner.py")
#   NODE2SHELL_FLAGS  extra flags, e.g. "-t 20 --timeout 30 -k"
set -euo pipefail
MODULE_NAME=node2shell
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

input="$(cat)"
urls="$(printf '%s\n' "$input" | read_values url || true)"
if [[ -z "${urls// }" ]]; then
  log "no input urls"
  exit 0
fi

read -ra bin <<<"${NODE2SHELL_BIN:-python3 /opt/node2shell/scanner.py}"
# Resolve: the binary/script must exist to run.
if ! command -v "${bin[0]}" >/dev/null 2>&1; then
  log "node2shell runner '${bin[0]}' not found -- skipping"
  exit 0
fi
if [[ "${bin[0]}" == python3 && -n "${bin[1]:-}" && ! -f "${bin[1]}" ]]; then
  log "node2shell scanner not found at ${bin[1]} -- skipping"
  exit 0
fi

read -ra extra <<<"${NODE2SHELL_FLAGS:-}"
list="$(mktemp)"; printf '%s\n' "$urls" > "$list"
out="$(mktemp)"
# -q: only vulnerable; -o: JSON output file.
if ! "${bin[@]}" -l "$list" -q -o "$out" "${extra[@]}" >&2 2>&2; then
  log "node2shell exited non-zero; parsing whatever it produced"
fi

python3 -c "$(cat <<'PY'
import json, sys
def emit(o):
    print(json.dumps(o)); sys.stdout.flush()
path = sys.argv[1]
try:
    doc = json.load(open(path))
except Exception:
    sys.exit(0)
# output may be a list of results or {"results":[...]}; handle both
rows = doc if isinstance(doc, list) else (doc.get("results") or doc.get("vulnerable") or [])
for r in rows:
    if not isinstance(r, dict):
        continue
    # treat presence in the (quiet) output as vulnerable unless explicitly false
    if r.get("vulnerable") is False:
        continue
    url = r.get("url") or r.get("target") or r.get("host")
    if not url:
        continue
    emit({"kind":"finding",
          "title":f"Node.js node2shell RCE (CVE-2026-111497): {url}",
          "severity":"critical","cvss_score":None,"cwe":None,
          "description":f"node2shell-scanner reports {url} vulnerable to CVE-2026-111497 "
                        f"(Node.js HTTP app). Mode: {r.get('mode') or r.get('comparison_mode') or 'n/a'}.",
          "evidence":[{"type":"text","label":"node2shell",
                       "content":json.dumps({k:r.get(k) for k in ('mode','comparison_mode','reason') if k in r})[:1000]}],
          "references":["https://nvd.nist.gov/vuln/detail/CVE-2026-111497",
                        "https://github.com/assetnote/node2shell-scanner"],
          "asset_ref":{"type":"url","value":url},
          "cve_id":"CVE-2026-111497","source_module":"node2shell",
          "dedup_key":f"node2shell:{url}"})
PY
)" "$out"
rm -f "$list" "$out"
