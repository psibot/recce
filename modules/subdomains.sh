#!/usr/bin/env bash
# subdomains -- enumerate subdomains for each input domain.
#   consumes: domain
#   produces: subdomain
#
# Wraps subfinder. This is the reference module: read input values, run the
# tool, emit records. Everything downstream (normalize/scope/ingest) is the
# orchestrator's job.
set -euo pipefail
MODULE_NAME=subdomains
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

# Buffer stdin so we can read it (module stdin is the concatenated input file).
input="$(cat)"

domains="$(printf '%s\n' "$input" | read_values domain || true)"
if [[ -z "${domains// }" ]]; then
  log "no input domains"
  exit 0
fi

if ! have subfinder; then
  log "subfinder not installed -- passing input domains through as-is"
  while IFS= read -r d; do
    [[ -n "$d" ]] && emit_asset subdomain "$d" '{"note":"passthrough: subfinder missing"}'
  done <<<"$domains"
  exit 0
fi

while IFS= read -r d; do
  [[ -z "$d" ]] && continue
  log "subfinder -d $d"
  # -silent: hostnames only, one per line
  while IFS= read -r sub; do
    [[ -n "$sub" ]] && emit_asset subdomain "$sub" "$(printf '{"root":"%s"}' "$d")"
  done < <(subfinder -silent -d "$d" 2>/dev/null || true)
done <<<"$domains"
