#!/usr/bin/env bash
# screenshots -- capture login/landing pages via Snapshot.
#   consumes: url
#   produces: screenshot
#
# Delegates to Snapshot (the self-hosted tool that screenshots and indexes
# login pages) instead of bundling a headless browser in the worker image.
# Requires SNAPSHOT_URL (and optionally SNAPSHOT_TOKEN); if unset, the module
# skips cleanly so the engine still runs.
set -euo pipefail
MODULE_NAME=screenshots
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

input="$(cat)"
urls="$(printf '%s\n' "$input" | read_values url || true)"
if [[ -z "${urls// }" ]]; then
  log "no input urls"
  exit 0
fi

if [[ -z "${SNAPSHOT_URL:-}" ]]; then
  log "SNAPSHOT_URL unset -- skipping (set it to enable Snapshot capture)"
  exit 0
fi

printf '%s\n' "$urls" \
| python3 "${RECCE_HOME:-/opt/recce}/helpers/py/snapshot_client.py" \
    --engagement "${RECCE_ENGAGEMENT:-}"
