#!/usr/bin/env python3
"""recce CVE intelligence — CVEngine-style prioritization.

Given CVE ids, this enriches them with the two signals that decide whether a
CVE actually matters, and folds them into a priority tier:

  * CISA KEV   — is the CVE on the Known Exploited Vulnerabilities catalog?
                 (one JSON feed; membership = actively exploited in the wild)
  * FIRST EPSS — probability (0..1) the CVE will be exploited in the next 30
                 days (a bulk API).

Tiers (mirrors CVEngine's fire / smoke / ice):
  fire   actively exploited or near-certain — KEV member, or EPSS >= 0.50,
         or a high EPSS with a high CVSS. Fix now.
  smoke  elevated — EPSS >= 0.10, or CVSS >= 7.0. Worth attention.
  ice    everything else — low signal right now.

Network feeds are fetched once per process and cached on disk; every fetch is
wrapped so that no network (air-gapped scan, blocked egress) degrades to "no
intel" rather than failing the run. All the scoring logic is pure and unit-
testable without a network (see tier()).

Env:
  RECCE_CVE_CACHE   cache dir (default: /tmp/recce-cve-cache)
  RECCE_CVE_OFFLINE if set to 1, skip all network fetches (use cache or nothing)
"""
import json
import os
import re
import time
import urllib.request

CACHE_DIR = os.environ.get("RECCE_CVE_CACHE", "/tmp/recce-cve-cache")
USER_AGENT = "recce-cve-intel/1.0"
KEV_TTL = 12 * 3600
EXPLOIT_TTL = 24 * 3600

# --- exploitation intelligence sources -----------------------------------
# "Is it exploited in the wild?" / "Is a public exploit available?" — the
# signals that drive the fire tier. Each loader degrades to empty on failure.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
# Exploit-DB: the files_exploits.csv index; its `codes` column carries CVE refs.
EXPLOITDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
# Metasploit: module metadata; each module's `references` carry CVE refs.
METASPLOIT_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
# VulnCheck KEV (community KEV, broader than CISA) — needs VULNCHECK_API_KEY.
VULNCHECK_KEV_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"
# ENISA EUVD exploited list (EU vulnerability database). Endpoint is overridable
# via RECCE_EUVD_URL since ENISA's API surface is still evolving.
EUVD_URL = os.environ.get(
    "RECCE_EUVD_URL",
    "https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities")
# CVE List V5 (official CVE records) — per-CVE raw JSON for description/CVSS.
CVELIST_V5_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
# cve.now aggregated feed (overridable; off unless a URL is provided).
CVENOW_URL = os.environ.get("RECCE_CVENOW_URL", "")


# --------------------------------------------------------------------------
# pure scoring  (no network — this is the part that's unit-tested)
# --------------------------------------------------------------------------
def tier(kev: bool, epss, cvss, has_exploit: bool = False) -> str:
    """Return 'fire' | 'smoke' | 'ice' from the available signals.

    Any signal may be missing (None); the function uses what it has.
    """
    e = float(epss) if epss is not None else None
    c = float(cvss) if cvss is not None else None

    # fire: proven or near-certain exploitation
    if kev or has_exploit:
        return "fire"
    if e is not None and e >= 0.50:
        return "fire"
    if e is not None and e >= 0.20 and c is not None and c >= 9.0:
        return "fire"

    # smoke: elevated likelihood or high severity
    if e is not None and e >= 0.10:
        return "smoke"
    if c is not None and c >= 7.0:
        return "smoke"

    return "ice"


def severity_from(kev: bool, priority: str, base_severity: str, cvss) -> str:
    """Decide a finding's severity given CVE intel, never lowering the base.

    KEV membership forces at least 'critical' (it's being exploited now);
    a 'fire' tier forces at least 'high'. Otherwise keep the larger of the
    base severity and what CVSS implies.
    """
    order = ["info", "low", "medium", "high", "critical"]
    def idx(s): return order.index(s) if s in order else 0

    base = base_severity if base_severity in order else "info"
    floor = base
    if cvss is not None:
        c = float(cvss)
        cvss_sev = ("critical" if c >= 9.0 else "high" if c >= 7.0 else
                    "medium" if c >= 4.0 else "low" if c > 0 else "info")
        if idx(cvss_sev) > idx(floor):
            floor = cvss_sev
    if priority == "fire" and idx("high") > idx(floor):
        floor = "high"
    if kev and idx("critical") > idx(floor):
        floor = "critical"
    return floor


# --------------------------------------------------------------------------
# feeds  (network, cached, always graceful)
# --------------------------------------------------------------------------
def _get(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _offline():
    return os.environ.get("RECCE_CVE_OFFLINE") == "1"


def load_kev(log=lambda *_: None):
    """Return a set of CVE ids on the CISA KEV catalog (empty on any failure)."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache = os.path.join(CACHE_DIR, "kev.json")
    if os.path.exists(cache) and (time.time() - os.path.getmtime(cache)) < KEV_TTL:
        try:
            return set(json.load(open(cache)))
        except Exception:
            pass
    if _offline():
        log("cve-intel: offline, no KEV cache")
        return set()
    try:
        data = json.loads(_get(KEV_URL))
        ids = [v["cveID"] for v in data.get("vulnerabilities", []) if v.get("cveID")]
        json.dump(ids, open(cache, "w"))
        log(f"cve-intel: loaded {len(ids)} KEV entries")
        return set(ids)
    except Exception as e:  # noqa: BLE001 — any failure degrades to no intel
        log(f"cve-intel: KEV fetch failed ({e}); continuing without KEV")
        # fall back to a stale cache if present
        try:
            return set(json.load(open(cache)))
        except Exception:
            return set()


def epss_for(cve_ids, log=lambda *_: None):
    """Return {cve_id: epss_float} for the given ids (missing ones omitted)."""
    ids = sorted({c for c in cve_ids if c})
    if not ids or _offline():
        return {}
    out = {}
    # FIRST EPSS takes a comma list; page to keep URLs sane.
    for i in range(0, len(ids), 100):
        batch = ids[i:i + 100]
        url = f"{EPSS_URL}?cve={','.join(batch)}"
        try:
            data = json.loads(_get(url))
            for row in data.get("data", []):
                cve = row.get("cve")
                score = row.get("epss")
                if cve and score is not None:
                    out[cve] = float(score)
        except Exception as e:  # noqa: BLE001
            log(f"cve-intel: EPSS fetch failed for batch ({e}); continuing")
    return out


CVE_ANY_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _cached_set(name, ttl, builder, log):
    """Load a set from disk cache (within ttl), else build + cache it."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache = os.path.join(CACHE_DIR, name)
    if os.path.exists(cache) and (time.time() - os.path.getmtime(cache)) < ttl:
        try:
            return set(json.load(open(cache)))
        except Exception:
            pass
    if _offline():
        try:
            return set(json.load(open(cache)))
        except Exception:
            return set()
    try:
        ids = builder()
        json.dump(sorted(ids), open(cache, "w"))
        return set(ids)
    except Exception as e:  # noqa: BLE001
        log(f"cve-intel: {name} fetch failed ({e}); continuing")
        try:
            return set(json.load(open(cache)))
        except Exception:
            return set()


def load_exploitdb(log=lambda *_: None):
    """CVEs that have a public Exploit-DB entry (from files_exploits.csv)."""
    def build():
        import csv, io
        raw = _get(EXPLOITDB_URL, timeout=60).decode("utf-8", "replace")
        ids = set()
        for row in csv.DictReader(io.StringIO(raw)):
            codes = row.get("codes") or ""
            for m in CVE_ANY_RE.finditer(codes):
                ids.add(m.group(0).upper())
        log(f"cve-intel: Exploit-DB → {len(ids)} CVEs with public exploits")
        return ids
    return _cached_set("exploitdb.json", EXPLOIT_TTL, build, log)


def load_metasploit(log=lambda *_: None):
    """CVEs covered by a Metasploit module (from modules_metadata_base.json)."""
    def build():
        data = json.loads(_get(METASPLOIT_URL, timeout=90))
        ids = set()
        for mod in (data.values() if isinstance(data, dict) else data):
            for ref in (mod.get("references") or []):
                m = CVE_ANY_RE.search(str(ref))
                if m:
                    ids.add(m.group(0).upper())
        log(f"cve-intel: Metasploit → {len(ids)} CVEs with modules")
        return ids
    return _cached_set("metasploit.json", EXPLOIT_TTL, build, log)


def load_vulncheck_kev(log=lambda *_: None):
    """VulnCheck community KEV (broader than CISA). Needs VULNCHECK_API_KEY."""
    key = os.environ.get("VULNCHECK_API_KEY")
    if not key:
        return set()

    def build():
        ids = set()
        # paginated API; pull a few pages defensively
        for page in range(0, 20):
            url = f"{VULNCHECK_KEV_URL}?limit=500&page={page}"
            req = urllib.request.Request(url, headers={
                "User-Agent": USER_AGENT, "Authorization": f"Bearer {key}"})
            with urllib.request.urlopen(req, timeout=40) as resp:
                data = json.loads(resp.read())
            rows = data.get("data") or []
            if not rows:
                break
            for r in rows:
                for c in (r.get("cve") or ([r.get("cveID")] if r.get("cveID") else [])):
                    if c:
                        ids.add(str(c).upper())
        log(f"cve-intel: VulnCheck KEV → {len(ids)} CVEs")
        return ids
    return _cached_set("vulncheck_kev.json", KEV_TTL, build, log)


def load_euvd(log=lambda *_: None):
    """ENISA EUVD exploited vulnerabilities (best-effort; endpoint evolving)."""
    def build():
        data = json.loads(_get(EUVD_URL, timeout=40))
        rows = data if isinstance(data, list) else (data.get("items") or data.get("data") or [])
        ids = set()
        for r in rows:
            blob = json.dumps(r)
            for m in CVE_ANY_RE.finditer(blob):
                ids.add(m.group(0).upper())
        log(f"cve-intel: ENISA EUVD → {len(ids)} CVEs")
        return ids
    return _cached_set("euvd.json", KEV_TTL, build, log)


def describe(cve, log=lambda *_: None):
    """Best-effort description + CVSS for one CVE from CVE List V5 raw JSON.

    Returns {"description": str|None, "cvss": float|None}. Used to backfill
    findings (e.g. from nmap/cvematch) that lack a description.
    """
    if _offline():
        return {"description": None, "cvss": None}
    try:
        year, num = cve.upper().split("-")[1], cve.upper().split("-")[2]
        bucket = num[:-3] + "xxx" if len(num) > 3 else "0xxx"
        url = f"{CVELIST_V5_BASE}/{year}/{bucket}/{cve.upper()}.json"
        data = json.loads(_get(url, timeout=25))
        cna = (data.get("containers") or {}).get("cna") or {}
        desc = None
        for d in (cna.get("descriptions") or []):
            if d.get("lang", "").startswith("en"):
                desc = d.get("value"); break
        cvss = None
        for m in (cna.get("metrics") or []):
            for k in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                if m.get(k, {}).get("baseScore") is not None:
                    cvss = float(m[k]["baseScore"]); break
            if cvss is not None:
                break
        return {"description": desc, "cvss": cvss}
    except Exception as e:  # noqa: BLE001
        log(f"cve-intel: CVE List V5 lookup failed for {cve} ({e})")
        return {"description": None, "cvss": None}


def enrich(cve_ids, cvss_by_cve=None, log=lambda *_: None):
    """One call: gather every exploitation signal and tier each CVE.

    Combines CISA KEV, VulnCheck KEV and ENISA EUVD (→ kev / exploited), plus
    Exploit-DB and Metasploit (→ public exploit available), plus FIRST EPSS,
    into the fire/smoke/ice tier. Returns, per CVE:
        {"kev": bool, "epss": float|None, "has_exploit": bool,
         "priority": tier, "sources": [str,...]}
    `kev` stays CISA-specific (what the KEV column means); the broader
    exploited/exploit signals are captured in `sources` and the tier.
    """
    cvss_by_cve = cvss_by_cve or {}
    ids = {c for c in cve_ids if c}
    cisa_kev = load_kev(log)
    vulncheck = load_vulncheck_kev(log)
    euvd = load_euvd(log)
    edb = load_exploitdb(log)
    msf = load_metasploit(log)
    epss = epss_for(ids, log)

    out = {}
    for cve in ids:
        sources = []
        if cve in cisa_kev: sources.append("CISA-KEV")
        if cve in vulncheck: sources.append("VulnCheck-KEV")
        if cve in euvd: sources.append("ENISA-EUVD")
        if cve in edb: sources.append("Exploit-DB")
        if cve in msf: sources.append("Metasploit")
        is_kev = cve in cisa_kev
        exploited = bool(sources) and any(
            s in ("CISA-KEV", "VulnCheck-KEV", "ENISA-EUVD") for s in sources)
        has_exploit = cve in edb or cve in msf
        e = epss.get(cve)
        c = cvss_by_cve.get(cve)
        out[cve] = {
            "kev": is_kev,
            "epss": e,
            "has_exploit": has_exploit,
            "priority": tier(is_kev or exploited, e, c, has_exploit),
            "sources": sources,
        }
    return out


if __name__ == "__main__":
    import sys
    ids = sys.argv[1:] or ["CVE-2021-44228"]
    print(json.dumps(enrich(ids, log=lambda m: print(m, file=sys.stderr)), indent=2))
