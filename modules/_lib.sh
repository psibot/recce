#!/usr/bin/env bash
# _lib.sh -- shared helpers sourced by every module.
#
# The module contract:
#   * stdin  : JSON-lines asset records of the module's `consumes` types
#   * stdout : JSON-lines records (assets and/or findings) the module produces
#   * stderr : human logging
#
# Modules never touch the database and never emit anything but records on
# stdout. Normalization, scope-gating and persistence happen downstream in the
# orchestrator pipeline (recce-normalize | recce-scope | recce-ingest).
#
# JSON is handled via python3 (guaranteed in the worker image) so values are
# always correctly escaped without a jq dependency.
#
# NOTE: helpers pass the python program via `-c "$(cat <<'PY' ...)"` so that
# stdin stays bound to the piped record data, not the heredoc script.

set -euo pipefail

log() { printf '[%s] %s\n' "${MODULE_NAME:-module}" "$*" >&2; }

# read_values <type> : read asset records from stdin, print bare `value` of
# records matching <type>, one per line.
read_values() {
  python3 -c "$(cat <<'PY'
import json, sys
want = sys.argv[1]
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        continue
    if rec.get("kind") == "asset" and rec.get("type") == want:
        v = rec.get("value")
        if v:
            print(v)
PY
)" "$1"
}

# emit_asset <type> <value> [attrs_json]
emit_asset() {
  local attrs="${3:-}"
  [[ -z "$attrs" ]] && attrs='{}'
  python3 -c "$(cat <<'PY'
import json, sys
t, v, attrs = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    a = json.loads(attrs)
except Exception:
    a = {}
print(json.dumps({"kind": "asset", "type": t, "value": v, "attrs": a}))
PY
)" "$1" "$2" "$attrs"
}

# emit_finding <json> : pass a complete finding object as JSON; kind injected.
emit_finding() {
  python3 -c "$(cat <<'PY'
import json, sys
rec = json.loads(sys.argv[1])
rec["kind"] = "finding"
print(json.dumps(rec))
PY
)" "$1"
}

# have <binary> -> 0 if present.
have() { command -v "$1" >/dev/null 2>&1; }
