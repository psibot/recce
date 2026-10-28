#!/usr/bin/env bash
# nmap -- service/version scan + CVE lookup via the vulners NSE script.
#   consumes: ip, subdomain, port
#   produces: port, service, finding
#
# Runs nmap -sV (service + version detection) and, when the vulners script is
# present, --script vulners, which maps each detected service+version to known
# CVEs with CVSS. Emits a `service` asset per open port and a `finding` per CVE
# (carrying cve_id + cvss, so the post-run enrich pass adds KEV/EPSS/priority).
#
# Config (env):
#   NMAP_PORTS   -p value (default: top ports; e.g. "1-1000" or "80,443,3389")
#   NMAP_FLAGS   extra flags, e.g. "-T4 --max-retries 2 -Pn"
#   NMAP_NO_VULN set to 1 to skip the vulners script (service scan only)
set -euo pipefail
MODULE_NAME=nmap
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

input="$(cat)"
# Prefer explicit IPs/hosts; also accept host:port `port` assets (take the host).
hosts="$( {
  printf '%s\n' "$input" | read_values ip
  printf '%s\n' "$input" | read_values subdomain
  printf '%s\n' "$input" | read_values port | sed 's/:[0-9]*$//'
} | sort -u | grep -v '^$' || true)"

if [[ -z "${hosts// }" ]]; then
  log "no input hosts"
  exit 0
fi

if ! have nmap; then
  log "nmap not installed -- skipping"
  exit 0
fi

# Does this nmap have the vulners script?
vuln_args=()
if [[ "${NMAP_NO_VULN:-}" != "1" ]] && nmap --script-help vulners >/dev/null 2>&1; then
  vuln_args=(--script vulners)
  log "vulners NSE present -- CVE lookup enabled"
else
  [[ "${NMAP_NO_VULN:-}" == "1" ]] || log "vulners NSE not found -- service scan only (install vulners.nse)"
fi

read -ra extra <<<"${NMAP_FLAGS:-}"
ports_arg=()
[[ -n "${NMAP_PORTS:-}" ]] && ports_arg=(-p "$NMAP_PORTS")

xml="$(mktemp)"
# Feed hosts via -iL. -sV drives both version detection and vulners.
if ! printf '%s\n' "$hosts" | nmap -sV "${vuln_args[@]}" "${ports_arg[@]}" "${extra[@]}" \
        -oX "$xml" -iL - >&2 2>&2; then
  log "nmap exited non-zero; parsing whatever XML it wrote"
fi

python3 -c "$(cat <<'PY'
import json, re, sys
import xml.etree.ElementTree as ET

def emit(o):
    print(json.dumps(o)); sys.stdout.flush()

path = sys.argv[1]
try:
    root = ET.parse(path).getroot()
except Exception as e:
    sys.stderr.write(f"[nmap] could not parse XML: {e}\n")
    sys.exit(0)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

for host in root.findall("host"):
    addr_el = host.find("address")
    addr = addr_el.get("addr") if addr_el is not None else None
    # best hostname if present
    hn = host.find(".//hostname")
    name = hn.get("name") if hn is not None else addr
    if not addr:
        continue
    for p in host.findall(".//port"):
        state = p.find("state")
        if state is None or state.get("state") != "open":
            continue
        portid = p.get("portid"); proto = p.get("protocol")
        svc = p.find("service")
        sname = svc.get("name") if svc is not None else None
        product = svc.get("product") if svc is not None else None
        version = svc.get("version") if svc is not None else None
        hostport = f"{name}:{portid}"

        emit({"kind":"asset","type":"port","value":f"{addr}:{portid}",
              "attrs":{"host":name,"ip":addr,"port":portid,"protocol":proto,"via":"nmap"}})
        emit({"kind":"asset","type":"service","value":f"{hostport}/{sname or 'unknown'}",
              "attrs":{"ip":addr,"port":portid,"service":sname,"product":product,
                       "version":version,"via":"nmap"}})

        # vulners script output: a table of CVEs with CVSS under this port.
        for script in p.findall("script"):
            if script.get("id") != "vulners":
                # still scan any script output text for CVE ids as a fallback
                pass
            out = script.get("output") or ""
            # vulners lines look like:  \tCVE-2021-1234\t7.5\thttps://...
            seen = set()
            for m in re.finditer(r"(CVE-\d{4}-\d{4,7})\s+([0-9.]+)?", out, re.I):
                cve = m.group(1).upper()
                if cve in seen:
                    continue
                seen.add(cve)
                try:
                    cvss = float(m.group(2)) if m.group(2) else None
                except ValueError:
                    cvss = None
                sev = ("critical" if cvss and cvss>=9 else "high" if cvss and cvss>=7
                       else "medium" if cvss and cvss>=4 else "low" if cvss else "info")
                svc_label = " ".join(x for x in (product, version) if x) or sname or ""
                emit({
                    "kind":"finding",
                    "title": f"{cve}: {svc_label} on {hostport}".strip(),
                    "severity": sev,
                    "cvss_score": cvss,
                    "cwe": None,
                    "description": f"nmap vulners matched {cve} to {svc_label or sname} "
                                   f"on {addr}:{portid}.",
                    "evidence": [{"type":"text","label":"nmap:vulners",
                                  "content": f"{addr}:{portid} {svc_label}".strip()}],
                    "references": [f"https://nvd.nist.gov/vuln/detail/{cve}"],
                    "asset_ref": {"type":"port","value":f"{addr}:{portid}"},
                    "cve_id": cve,
                    "source_module": "nmap",
                    "dedup_key": f"nmap:{cve}:{addr}:{portid}",
                })
PY
)" "$xml"
rm -f "$xml"
