#!/usr/bin/env bash
# fuzzing -- directory/content discovery (reNgine's dir fuzzing).
#   consumes: url
#   produces: endpoint, finding
#
# Wraps ffuf. A wordlist is NOT baked into the image to keep it lean — set
# FFUF_WORDLIST to a list you mount (e.g. a SecLists path). Without it, this
# module skips cleanly so the engine still runs.
#
# Config (env):
#   FFUF_WORDLIST  path to a wordlist (required to run)
#   FFUF_MATCH     comma status codes to match (default 200,204,301,302,307,401,403)
#   FFUF_FLAGS     extra ffuf flags, e.g. "-t 50 -rate 200"
set -euo pipefail
MODULE_NAME=fuzzing
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

input="$(cat)"
urls="$(printf '%s\n' "$input" | read_values url || true)"
if [[ -z "${urls// }" ]]; then
  log "no input urls"
  exit 0
fi

if ! have ffuf; then
  log "ffuf not installed -- skipping"
  exit 0
fi

wordlist="${FFUF_WORDLIST:-}"
if [[ -z "$wordlist" || ! -f "$wordlist" ]]; then
  log "FFUF_WORDLIST unset or missing -- skipping (mount a wordlist and set FFUF_WORDLIST)"
  exit 0
fi

match="${FFUF_MATCH:-200,204,301,302,307,401,403}"
read -ra extra <<<"${FFUF_FLAGS:-}"

# De-dupe seed URLs to their scheme://host base so we fuzz each host once.
bases="$(python3 -c "$(cat <<'PY'
import sys
from urllib.parse import urlsplit
seen=set()
for line in sys.stdin:
    u=line.strip()
    if not u: continue
    p=urlsplit(u)
    if not p.scheme or not p.netloc: continue
    base=f"{p.scheme}://{p.netloc}"
    if base not in seen:
        seen.add(base); print(base)
PY
)" <<<"$urls")"

while IFS= read -r base; do
  [[ -z "$base" ]] && continue
  tmp="$(mktemp)"
  log "ffuf $base/FUZZ"
  # -of json writes a structured report; -s keeps ffuf quiet on stdout.
  ffuf -u "$base/FUZZ" -w "$wordlist" -mc "$match" -s -of json -o "$tmp" "${extra[@]}" 2>&2 || \
    log "ffuf non-zero on $base (parsing partial output)"
  python3 -c "$(cat <<'PY'
import json, sys
base = sys.argv[1]
path = sys.argv[2]
def emit(o):
    print(json.dumps(o)); sys.stdout.flush()  # stream per record
try:
    doc = json.load(open(path))
except Exception:
    sys.exit(0)
for r in doc.get("results", []):
    url = r.get("url") or ""
    status = r.get("status")
    length = r.get("length")
    if not url:
        continue
    emit({"kind":"asset","type":"endpoint","value":url,
          "attrs":{"status":status,"length":length,"words":r.get("words"),"via":"ffuf"}})
    # Surface auth-gated admin-ish paths as a low finding worth a look.
    low = url.lower()
    if status in (401,403) and any(k in low for k in ("admin","internal","backup",".git","config","dashboard")):
        emit({"kind":"finding","title":f"Protected sensitive path exposed: {url}",
              "severity":"low","description":f"ffuf found {url} returning {status} (exists but access-controlled).",
              "evidence":[{"type":"text","label":"ffuf","content":f"{status} {url} len={length}"}],
              "references":[],"asset_ref":{"type":"endpoint","value":url},
              "source_module":"fuzzing","dedup_key":f"ffuf:protected:{url}"})
PY
)" "$base" "$tmp"
  rm -f "$tmp"
done <<<"$bases"
