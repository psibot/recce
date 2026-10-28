#!/usr/bin/env bash
# run-engine.sh -- the bash core.
#
# Reads a declarative engine (YAML), then runs its modules in order. For each
# module it builds input from the working files of the types the module
# consumes, runs the module, and pipes the output through the three-language
# contract:
#
#     module.sh | recce-normalize | recce-scope | recce-ingest
#        (bash)       (Go)             (Go)          (Python)
#
# recce-ingest writes to Postgres AND appends in-scope assets to
# $WORKDIR/assets/<type>.jsonl, which is how the next module gets its input.
#
# Usage:
#   run-engine.sh --engagement <uuid> --engine <name> [--run <uuid>] [--workdir <dir>]
#
# Env:
#   DATABASE_URL   required (Python helpers use it)
#   RECCE_HOME     repo root (default: parent of this script's dir)
#   RECCE_BIN      dir with recce-normalize / recce-scope (default: $RECCE_HOME/bin)
set -euo pipefail

RECCE_HOME="${RECCE_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
RECCE_BIN="${RECCE_BIN:-$RECCE_HOME/bin}"
PY="$RECCE_HOME/helpers/py"
MODULES="$RECCE_HOME/modules"
ENGINES="$RECCE_HOME/engines"

NORMALIZE="$RECCE_BIN/recce-normalize"
SCOPE="$RECCE_BIN/recce-scope"
INGEST=("python3" "$PY/ingest.py")
ENG=("python3" "$PY/engagement.py")

engagement="" engine="" run_id="" workdir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --engagement) engagement="$2"; shift 2;;
    --engine)     engine="$2"; shift 2;;
    --run)        run_id="$2"; shift 2;;
    --workdir)    workdir="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[[ -n "$engagement" && -n "$engine" ]] || { echo "need --engagement and --engine" >&2; exit 2; }

engine_file="$ENGINES/$engine.yml"
[[ -f "$engine_file" ]] || { echo "no such engine: $engine_file" >&2; exit 2; }

# Fail fast if the Go helpers aren't built.
for b in "$NORMALIZE" "$SCOPE"; do
  [[ -x "$b" ]] || { echo "missing helper: $b (run 'make build')" >&2; exit 3; }
done

workdir="${workdir:-$(mktemp -d /tmp/recce.XXXXXX)}"
mkdir -p "$workdir/assets"
scope_file="$workdir/scope.json"

# Create a run row if we weren't handed one.
if [[ -z "$run_id" ]]; then
  run_id="$("${ENG[@]}" create-run --engagement "$engagement" --engine "$engine")"
fi
echo "run_id=$run_id workdir=$workdir" >&2

cleanup_status="failed"
finish() { "${ENG[@]}" run-finish --run "$run_id" --status "$cleanup_status" || true; }
trap finish EXIT

"${ENG[@]}" run-start --run "$run_id"
# Materialize scope.json + seed domain.jsonl from the DB.
"${ENG[@]}" prepare --engagement "$engagement" --workdir "$workdir"

# Modules that need engagement/run context (e.g. screenshots -> Snapshot) read
# these from the environment.
export RECCE_ENGAGEMENT="$engagement" RECCE_RUN="$run_id"

# Resolve the engine into a real execution order (topological sort by
# consumes/produces), not just file order. Output: name<TAB>consumes_csv.
mapfile -t plan < <(python3 "$PY/plan.py" "$engine_file")

for entry in "${plan[@]}"; do
  # plan.py emits: name<TAB>consumes_csv<TAB>config_json
  name="${entry%%$'\t'*}"
  rest="${entry#*$'\t'}"
  consumes_csv="${rest%%$'\t'*}"
  config_json="${rest#*$'\t'}"
  mod="$MODULES/$name.sh"
  if [[ ! -x "$mod" ]]; then
    echo "skip $name (no executable module at $mod)" >&2
    continue
  fi

  # Turn this module's engine config into KEY=VAL env args, applied only to the
  # module process (via `env`), so one engine's BBOT_PRESET/FFUF_WORDLIST/etc.
  # doesn't leak into other modules or override the worker env globally.
  cfg_env=()
  if [[ -n "$config_json" && "$config_json" != "{}" ]]; then
    mapfile -t cfg_env < <(printf '%s' "$config_json" | python3 -c 'import json,sys
d=json.load(sys.stdin) or {}
for k,v in d.items(): print(f"{k}={v}")')
    [[ ${#cfg_env[@]} -gt 0 ]] && echo "    config: ${cfg_env[*]}" >&2
  fi

  # Build this module's input from the working files of its consumed types.
  input="$workdir/input.$name.jsonl"
  : > "$input"
  IFS=',' read -r -a types <<<"$consumes_csv"
  for t in "${types[@]}"; do
    [[ -z "$t" ]] && continue
    [[ -f "$workdir/assets/$t.jsonl" ]] && cat "$workdir/assets/$t.jsonl" >> "$input"
  done

  echo ">>> module $name (consumes: ${consumes_csv:-none}, input lines: $(wc -l < "$input"))" >&2
  mr="$("${ENG[@]}" module-start --run "$run_id" --module "$name")"

  # The three-language pipeline. `set -o pipefail` makes a failure anywhere
  # fail the module. `env "${cfg_env[@]}"` applies engine config to the module
  # process only (empty array -> plain env, a no-op passthrough).
  if env "${cfg_env[@]}" "$mod" < "$input" \
        | "$NORMALIZE" \
        | "$SCOPE" -rules "$scope_file" \
        | "${INGEST[@]}" --engagement "$engagement" --run "$run_id" \
                         --module "$name" --workdir "$workdir/assets"; then
    "${ENG[@]}" module-finish --module-run "$mr" --status done
  else
    echo "!!! module $name failed" >&2
    "${ENG[@]}" module-finish --module-run "$mr" --status failed
  fi
done

# CVE prioritization pass (CVEngine-style): enrich CVE-bearing findings with
# CISA KEV + FIRST EPSS and a fire/smoke/ice tier. Non-fatal — a feed outage
# must not fail an otherwise-complete run.
echo ">>> enrich: CVE prioritization (KEV + EPSS)" >&2
if ! python3 "$PY/enrich_cves.py" --engagement "$engagement" --run "$run_id"; then
  echo "!!! CVE enrichment pass failed (continuing; findings are still saved)" >&2
fi

cleanup_status="done"
echo "engine '$engine' complete for run $run_id" >&2
