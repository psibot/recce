#!/usr/bin/env bash
# cvematch -- correlate discovered tech+version to known CVEs (CVEngine-style).
#   consumes: tech
#   produces: finding
#
# For each `tech` asset that carries a version, queries the NVD 2.0 API for CVEs
# affecting that product+version and emits a finding per CVE. The post-run
# enrich_cves pass then adds KEV/EPSS/priority. This is best-effort correlation
# (keyword/CPE matching is inherently noisy) — the reliable CVE signal remains
# nuclei; cvematch widens coverage to versioned tech nuclei has no template for.
#
# Config (env):
#   NVD_API_KEY   optional NVD key (higher rate limit; strongly recommended)
#   CVE_MIN_CVSS  only emit CVEs at/above this CVSS (default 7.0) to cut noise
#   RECCE_CVE_OFFLINE=1  skip entirely (air-gapped)
set -euo pipefail
MODULE_NAME=cvematch
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

input="$(cat)"
if [[ "${RECCE_CVE_OFFLINE:-}" == "1" ]]; then
  log "RECCE_CVE_OFFLINE=1 -- skipping CVE correlation"
  exit 0
fi

# tech assets carry product in `value` and version in attrs.version (when known).
# Emit "product\tversion" lines for those that have a version.
pairs="$(printf '%s\n' "$input" | python3 -c "$(cat <<'PY'
import json, sys
seen = set()
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        r = json.loads(line)
    except json.JSONDecodeError:
        continue
    if r.get("kind") != "asset" or r.get("type") != "tech":
        continue
    product = (r.get("value") or "").strip()
    attrs = r.get("attrs") or {}
    version = str(attrs.get("version") or "").strip()
    # httpx often packs "Nginx:1.18.0" style; split if so
    if not version and ":" in product:
        product, _, version = product.rpartition(":")
    if product and version and (product, version) not in seen:
        seen.add((product, version))
        print(f"{product}\t{version}")
PY
)")"

if [[ -z "${pairs// }" ]]; then
  log "no versioned tech to correlate"
  exit 0
fi

n=$(printf '%s\n' "$pairs" | grep -c . || true)
log "correlating $n product:version pair(s) against NVD"

printf '%s\n' "$pairs" | python3 -c "$(cat <<'PY'
import json, os, sys, time, urllib.parse, urllib.request

MIN = float(os.environ.get("CVE_MIN_CVSS", "7.0"))
KEY = os.environ.get("NVD_API_KEY")
BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def emit(o):
    print(json.dumps(o)); sys.stdout.flush()  # stream per record

def nvd(product, version):
    # keywordSearch is looser than CPE but needs no CPE dictionary; we gate on
    # CVSS to control noise. Quote the product+version as the search terms.
    q = urllib.parse.urlencode({"keywordSearch": f"{product} {version}",
                                "resultsPerPage": "50"})
    req = urllib.request.Request(f"{BASE}?{q}", headers={
        "User-Agent": "recce-cvematch/1.0",
        **({"apiKey": KEY} if KEY else {}),
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())

for line in sys.stdin:
    line = line.rstrip("\n")
    if not line.strip():
        continue
    product, _, version = line.partition("\t")
    try:
        data = nvd(product, version)
    except Exception as e:
        sys.stderr.write(f"[cvematch] NVD query failed for {product} {version}: {e}\n")
        continue
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id")
        if not cid:
            continue
        # pick the best CVSS available (v3.1 > v3.0 > v2)
        metrics = cve.get("metrics", {})
        score = None
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(k):
                score = metrics[k][0].get("cvssData", {}).get("baseScore")
                break
        if score is not None and float(score) < MIN:
            continue
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"),
                    descs[0]["value"] if descs else cid)
        sev = ("critical" if score and score >= 9 else "high" if score and score >= 7
               else "medium" if score and score >= 4 else "low" if score else "info")
        emit({
            "kind": "finding",
            "title": f"{cid}: {product} {version}",
            "severity": sev,
            "cvss_score": float(score) if score is not None else None,
            "cwe": None,
            "description": desc[:500],
            "evidence": [{"type": "text", "label": "cvematch",
                          "content": f"NVD keyword match: {product} {version}"}],
            "references": [f"https://nvd.nist.gov/vuln/detail/{cid}"],
            "asset_ref": None,
            "cve_id": cid,
            "source_module": "cvematch",
            "dedup_key": f"cvematch:{cid}:{product}:{version}",
        })
    # NVD asks for <= 5 req/s without a key; be polite.
    time.sleep(0.8 if KEY else 6.0)
PY
)"
