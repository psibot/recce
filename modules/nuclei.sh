#!/usr/bin/env bash
# nuclei -- template-based scanning against live URLs.
#   consumes: url
#   produces: finding
#
# Maps nuclei JSONL output into Dossier-shaped finding records (severity,
# cvss, cwe, evidence block, references, asset_ref, stable dedup_key).
set -euo pipefail
MODULE_NAME=nuclei
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

input="$(cat)"
urls="$(printf '%s\n' "$input" | read_values url || true)"
if [[ -z "${urls// }" ]]; then
  log "no input urls"
  exit 0
fi

if ! have nuclei; then
  log "nuclei not installed -- skipping"
  exit 0
fi

# Surface nuclei's stderr to the run console (no /dev/null) and parse whatever
# it produced even on a non-zero exit. We deliberately do NOT pass -duc: it
# suppresses nuclei's template download, so a template-less image fails with
# "no templates provided for scan". Without it, nuclei uses the baked templates
# and self-heals (re-fetches) if they're ever missing.
# Stream: nuclei emits each match as it finds it (-jsonl), and we parse each
# line straight into a record on stdout — no capture-to-file, no waiting for
# nuclei to finish. Combined with the Go helpers flushing per line and ingest
# committing incrementally, findings land in the DB progressively, so a long
# run shows results live and a timeout/kill keeps everything already found.
# NUCLEI_FLAGS lets you tune for big inputs, e.g. "-c 50 -rl 150 -timeout 8".
read -ra nflags <<<"${NUCLEI_FLAGS:-}"
set +o pipefail  # nuclei's own exit must not kill the module mid-stream
printf '%s\n' "$urls" | nuclei -silent -jsonl "${nflags[@]}" 2>&2 \
| python3 -c "$(cat <<'PY'
import json, sys

def emit(o):
    print(json.dumps(o))
    sys.stdout.flush()  # stream: push each finding out as nuclei reports it

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        n = json.loads(line)
    except json.JSONDecodeError:
        continue
    info = n.get("info", {}) or {}
    classification = info.get("classification", {}) or {}
    cwe_list = classification.get("cwe-id") or []
    cwe = cwe_list[0].upper() if cwe_list else None
    cvss = classification.get("cvss-score")
    matched = n.get("matched-at") or n.get("host") or ""
    template = n.get("template-id") or info.get("name") or "nuclei"

    finding = {
        "kind": "finding",
        "title": info.get("name") or template,
        "severity": (info.get("severity") or "info").lower(),
        "cvss_score": cvss,
        "cvss_vector": classification.get("cvss-metrics"),
        "cwe": cwe,
        "description": info.get("description"),
        "remediation": info.get("remediation"),
        "references": info.get("reference") or [],
        "evidence": [{
            "type": "text",
            "label": f"nuclei:{template}",
            "content": n.get("matcher-name") or matched,
            "request": n.get("request"),
            "response": n.get("response"),
        }],
        "asset_ref": {"type": "url", "value": matched},
        "dedup_key": f"nuclei:{template}:{matched}",
    }
    emit(finding)
PY
)"
# nuclei's exit code is first in the pipe; log a non-zero without failing.
nuclei_rc="${PIPESTATUS[1]}"
set -o pipefail
if [[ "${nuclei_rc:-0}" -ne 0 ]]; then
  log "nuclei exited non-zero (rc=$nuclei_rc); streamed findings are already committed"
fi
