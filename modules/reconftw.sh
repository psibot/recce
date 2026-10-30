#!/usr/bin/env bash
# reconftw -- deep recon via six2dez/reconftw, results harvested into recce.
#   consumes: domain
#   produces: subdomain, url, ip
#
# reconftw is itself a large recon orchestrator. This module runs it per domain,
# then harvests its output tree (which varies across versions) by globbing the
# well-known result files — subdomains, resolved IPs, and live web URLs — and
# emits them as recce assets so they flow through the normal pipeline.
#
# reconftw is heavy and slow. Keep it light with RECONFTW_MODE=-s (subdomains)
# or -p (passive); -r is full recon. Skips cleanly if reconftw.sh isn't found.
#
# Config (env):
#   RECONFTW_BIN    path to reconftw.sh (default: reconftw.sh on PATH, else
#                   /opt/reconftw/reconftw.sh)
#   RECONFTW_MODE   mode flag (default: -s). -p passive, -r recon, -a active.
#   RECONFTW_FLAGS  extra flags, e.g. "--deep"
set -euo pipefail
MODULE_NAME=reconftw
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

input="$(cat)"
domains="$(printf '%s\n' "$input" | read_values domain || true)"
if [[ -z "${domains// }" ]]; then
  log "no input domains"
  exit 0
fi

bin="${RECONFTW_BIN:-}"
if [[ -z "$bin" ]]; then
  # Prefer the REAL install (its lib/ and modules/ are sourced relative to the
  # script's own dir, so a PATH symlink breaks it). Fall back to PATH.
  if   [[ -f /opt/reconftw/reconftw.sh ]]; then bin="/opt/reconftw/reconftw.sh"
  elif have reconftw.sh; then bin="$(command -v reconftw.sh)"
  fi
fi
# Resolve symlinks so we invoke the script at its real location (reconftw
# computes its base dir from its own path and sources lib/*.sh from there).
bin="$(readlink -f "$bin" 2>/dev/null || echo "$bin")"
if [[ -z "$bin" || ! -f "$bin" ]]; then
  log "reconftw.sh not found -- skipping (set RECONFTW_BIN or install to /opt/reconftw)"
  exit 0
fi
rdir="$(cd "$(dirname "$bin")" && pwd)"
rname="$(basename "$bin")"
if [[ ! -d "$rdir/lib" && ! -d "$rdir/modules" ]]; then
  log "reconftw libs not found next to $bin -- skipping (incomplete install)"
  exit 0
fi

mode="${RECONFTW_MODE:--s}"
read -ra extra <<<"${RECONFTW_FLAGS:-}"
outroot="$(mktemp -d)"

while IFS= read -r d; do
  [[ -z "$d" ]] && continue
  log "reconftw $mode -d $d (this can take a while)"
  # Run from reconftw's own dir so it finds lib/*.sh and modules/*.sh.
  # -o sets output dir; reconftw writes under $outroot/<domain>/...
  ( cd "$rdir" && "./$rname" -d "$d" "$mode" -o "$outroot" "${extra[@]}" ) >&2 2>&2 || \
    log "reconftw exited non-zero for $d; harvesting whatever it wrote"
done <<<"$domains"

# Harvest the output tree defensively: filenames/paths vary across reconftw
# versions, so match by pattern rather than a fixed layout.
python3 -c "$(cat <<'PY'
import glob, json, os, re, sys
root = sys.argv[1]
def emit(o):
    print(json.dumps(o)); sys.stdout.flush()

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]+$")

def read_lines(patterns):
    seen = set()
    for pat in patterns:
        for path in glob.glob(os.path.join(root, "**", pat), recursive=True):
            try:
                for ln in open(path, errors="replace"):
                    ln = ln.strip()
                    if ln and ln not in seen:
                        seen.add(ln); yield ln
            except OSError:
                continue

# subdomains
for host in read_lines(["subdomains.txt", "subdomains_*.txt", "*subdomains*.txt"]):
    if " " in host or "/" in host:
        continue
    emit({"kind":"asset","type":"subdomain","value":host,"attrs":{"via":"reconftw"}})

# resolved IPs
for line in read_lines(["ips.txt", "ip.txt", "*ips*.txt", "hosts/*.txt"]):
    tok = line.split()[0]
    if IP_RE.match(tok):
        emit({"kind":"asset","type":"ip","value":tok,"attrs":{"via":"reconftw"}})

# live web servers / urls
for url in read_lines(["webs.txt", "webs_all.txt", "web_full_info.txt", "*webs*.txt", "urls.txt", "*url*.txt"]):
    tok = url.split()[0]
    if tok.startswith("http://") or tok.startswith("https://"):
        emit({"kind":"asset","type":"url","value":tok,"attrs":{"via":"reconftw"}})

# newer reconftw asset store (JSONL) if present
for path in glob.glob(os.path.join(root, "**", "assets.jsonl"), recursive=True):
    try:
        for ln in open(path, errors="replace"):
            ln = ln.strip()
            if not ln:
                continue
            try:
                a = json.loads(ln)
            except json.JSONDecodeError:
                continue
            host = a.get("host") or a.get("name") or a.get("subdomain")
            if host and "." in host and " " not in host:
                emit({"kind":"asset","type":"subdomain","value":host,"attrs":{"via":"reconftw"}})
    except OSError:
        continue
PY
)" "$outroot"
rm -rf "$outroot"
