# recce

A self-hosted, reNgine-style recon framework with a **bash core**. Bash
orchestrates and executes; it drops into **Go** for the hot paths and
**Python** for anything touching the database, the API, or the queue. Findings
land in a **Dossier-native schema** so reporting is a query, not an export.


## Why this shape

Three tiers with a queue in the middle, so a seconds-long HTTP request never
blocks on an hours-long scan:

```
 Web/API (FastAPI)  --enqueue-->  Redis  --pull-->  Worker
   engagements                                        |
   scope, users                                       v
   list assets/findings                        orchestrator (bash)
                                                       |
                          module.sh | recce-normalize | recce-scope | recce-ingest
                             bash         Go               Go            Python
```

The two contracts everything hangs off:

1. **The store** — `db/schema.sql`. `assets` (dedup + provenance for run-to-run
   diffing) and `findings` (Dossier-shaped: cvss, cwe, evidence blocks,
   remediation, status workflow).
2. **The module I/O contract** — a module reads JSON-lines asset records of the
   types it `consumes` on stdin and emits records (assets and/or findings) on
   stdout. Nothing else. Normalization, scope-gating and persistence are the
   orchestrator's job.

## The three-language pipeline

Every module's output flows through the same pipe, which is also the template
for calling Go and Python from bash generally:

- **`recce-normalize`** (Go, stdlib) — canonicalize values, drop in-stream dupes.
- **`recce-scope`** (Go, stdlib) — the scope gate. Enforced here in the worker,
  never only in the UI, so a job can't wander out of scope. Fails closed.
- **`recce-ingest`** (Python) — the *only* writer to Postgres. Upserts assets
  and Dossier-shaped findings, and appends in-scope assets to
  `workdir/assets/<type>.jsonl` so the next module gets its input.

Go helpers are static binaries on `$PATH`, called like any other tool. Python
helpers are stdin/stdout JSON filters. The interface between all three is JSON
lines + exit codes — the same Unix contract you've used for years.

## Declarative engines

`engines/default.yml` defines the module DAG. The (future) UI edits this file;
the orchestrator executes it. Adding a tool = a new module script + a line in
the engine, no orchestrator changes.

## Quickstart

```bash
# 1. build the Go helpers (needs Go on the host)
make build

# 2. offline smoke test — proves normalize + scope with no tools installed
make smoke

# 3. bring up the stack
cp .env.example .env      # edit secrets
make up                   # web on :8000, minio console :9001

# 4. drive it
curl -s localhost:8000/engagements -H 'content-type: application/json' \
     -d '{"name":"Acme External"}'                    # -> {id,...}
E=<id-from-above>
curl -s localhost:8000/engagements/$E/scope -H 'content-type: application/json' \
     -d '{"kind":"include","pattern_type":"domain","value":"example.com"}'
curl -s localhost:8000/engagements/$E/scans -H 'content-type: application/json' \
     -d '{"engine":"default"}'                        # -> {run_id,...}
curl -s localhost:8000/engagements/$E/findings
```

Put the web tier behind Nginx Proxy Manager with Authentik/Keycloak SSO;
scale workers with `docker compose up -d --scale worker=4`.

## Adding a module

1. Drop `modules/<name>.sh`, `source _lib.sh`, read inputs with `read_values`,
   emit with `emit_asset` / `emit_finding`. Degrade gracefully if the tool is
   missing (`have <tool>`), so the pipeline stays testable.
2. Add it to an engine YAML with `consumes` / `produces`.

That's it — normalize, scope, ingest, dedup, provenance and diffing come for
free from the pipeline.

## Dossier integration

`findings` is shaped to be read directly by Dossier — same Postgres, no
import/export. Point Dossier at this DB (or a view over it) and recon →
findings → report is one loop. This is the piece no off-the-shelf recon
framework gives you.

For a decoupled workflow, each engagement also exports on demand:

- `GET /engagements/<id>/export?format=nuclei` → **Nuclei JSONL**, importable
  today via Dossier's built-in Nuclei importer (zero adapter).
- `GET /engagements/<id>/export?format=dossier` → a **lossless recce bundle**
  (engagement, scope, assets, findings with every Dossier field) for a native
  importer. Both are downloadable from the console's "Export → Dossier" panel.

## Status: v0.8

Added in v0.8 — more scanners, nmap vuln scan, delete, wider exploit intel:

- **Delete engagement** — `DELETE /engagements/<id>` and a delete button in the
  UI (with a confirm showing asset/finding counts). One delete cascades to
  scope, runs, assets and findings (verified against a live DB).
- **`nmap` module** — `nmap -sV` service/version detection plus the **vulners**
  NSE script for CVE lookup. Emits `service` assets and CVE `finding`s (with
  cve_id + CVSS, so the CVE-intel pass tiers them). `NMAP_PORTS`/`NMAP_FLAGS`
  tune it; `NMAP_NO_VULN=1` for service-scan only.
- **New scanner modules:** `gowitness` (headless screenshots → `screenshot`),
  `wpscan` (WordPress vulns — runs only on hosts fingerprinted WordPress),
  `node2shell` (CVE-2026-111497 in Node.js apps), `rdp` (RDP exposure + NLA
  probe via aardwolf). naabu and wafw00f were already in (`portscan`, `waf`).
- **Exploitation intelligence expanded** — CVE tiering now fuses **CISA KEV,
  VulnCheck KEV, ENISA EUVD** (→ exploited-in-the-wild) and **Exploit-DB +
  Metasploit** (→ public exploit available, drives the `fire` tier), on top of
  **FIRST EPSS**, with **CVE List V5** for description/CVSS backfill. Each
  finding records which sources flagged it. All source-merge logic unit-tested.
- **New engines:** `vuln-scan` (full assessment: discovery → nmap/nuclei/
  cvematch → wpscan/node2shell → gowitness/rdp → CVE tiering); `nmap` and
  `gowitness` added to `full-scan`.
- **Image:** nmap+vulners and gowitness+chromium are core; wpscan (Ruby),
  node2shell (git) and aardwolf (pip) install best-effort so a fragile build
  doesn't brick the image — the module simply skips if its tool is absent.

Note: the newer third-party scanners are wrapped to recce's contract and their
parsers are fixture-tested, but each should be validated against its live tool
in your environment (CLIs/outputs drift). nmap (service + vulners parsing), the
CVE-intel source merge, and the delete cascade were verified end-to-end here.

Added in v0.7 — streaming pipeline (progressive commit):

- **The whole pipeline now streams per-record.** nuclei pipes its matches
  straight through the parser as it finds them (no capture-to-file), the Go
  helpers (`recce-normalize`, `recce-scope`) flush each line instead of
  buffering to EOF, every module parser flushes per record, and `recce-ingest`
  commits every `RECCE_COMMIT_EVERY` records (default 100). So a long scan over
  thousands of URLs shows findings land **progressively** in the DB/UI, and a
  timeout or kill **keeps everything already found** instead of losing the lot.
  Verified end-to-end against a live Postgres: rows appear mid-stream, and 6/6
  survived a mid-run `kill -9`.
- **Why not literally one-URL-at-a-time:** nuclei reloads its full template set
  (thousands) on every launch, so per-URL invocation would be far slower.
  Streaming a single invocation gives the same progressive-commit benefit
  without that penalty. Tune throughput with `NUCLEI_FLAGS` (e.g.
  `-c 50 -rl 150 -timeout 8`).

Added in v0.6 — CVE intelligence (CVEngine-style prioritization):

- **CVE prioritization pass** (`helpers/py/cve_intel.py` + `enrich_cves.py`) —
  after an engine runs, every CVE-bearing finding (nuclei names its templates
  `CVE-xxxx`, cvematch sets `cve_id`) is enriched with **CISA KEV** (actively
  exploited?) and **FIRST EPSS** (exploit probability), then tiered
  **fire / smoke / ice** like CVEngine. KEV membership raises a finding to
  `critical`; a `fire` tier to at least `high` (severity is never lowered). The
  reasoning is written into the finding as a `cve-intel` evidence block.
- **`cvematch` module** — correlates discovered `tech`+version against the NVD
  2.0 API for CVEs nuclei has no template for (best-effort keyword/CPE match,
  gated by `CVE_MIN_CVSS` to cut noise). `NVD_API_KEY` lifts the rate limit.
- **Graceful offline** — all CVE feeds degrade cleanly: no network (air-gapped,
  or `RECCE_CVE_OFFLINE=1`) means findings still tier from CVSS alone and the
  run stays successful. KEV is cached on disk (12h TTL).
- **Schema** — findings gain `cve_id`, `kev`, `epss`, `priority` (additive;
  `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` migrates existing DBs on re-apply).
- **Surfaced everywhere** — findings sort fire-first in the API, UI (new
  priority/KEV/CVE/EPSS columns), and PDF (tier + KEV + EPSS per finding, plus
  a "X on CISA KEV" summary line). New `cve-scan` engine; `cvematch` added to
  `full-scan`.

All prioritization logic is unit-tested (tier truth table, severity bump, KEV/
EPSS parsing, CVE extraction) and the DB enrichment pass was verified end-to-end
against a live Postgres.

Added in v0.5:

- **Per-module engine config** — an engine's module entry can carry a `config:`
  map of `ENV_VAR: value` that the orchestrator applies to *that module's
  process only* (via `env`, so it never leaks to other modules or overrides the
  worker env globally). Engines are now self-contained: `passive` pins BBOT to
  `-rf passive`, `bbot-recon` sets its own `BBOT_PRESET`, and you can set
  `FFUF_WORDLIST` per engine. `plan.py` emits the config; the orchestrator
  scopes it. See the schema comment in `engines/default.yml`.
- **PDF findings report** — `GET /engagements/<id>/export?format=pdf` renders a
  printable report (title block, colored severity summary, per-finding blocks
  with CVSS/CWE/module/asset, description, remediation, evidence, references),
  built with reportlab (pure Python, no system libs). Export buttons (PDF /
  JSON / nuclei) are in the findings panel. Joins the existing `dossier` and
  `nuclei` export formats, all from the same `fetch_bundle` source of truth.

Added in v0.4 — BBOT + reNgine parity:

- **`bbot` module** — wraps [BBOT](https://github.com/blacklanternsecurity/bbot),
  the recursive recon engine, as a single module and maps its NDJSON event
  stream onto recce's typed records: `DNS_NAME`→subdomain, `IP_ADDRESS`→ip,
  `OPEN_TCP_PORT`→port, `URL`→url, `TECHNOLOGY`→tech, `EMAIL_ADDRESS`→email,
  `STORAGE_BUCKET`→bucket, `ASN`→asn, and `FINDING`/`VULNERABILITY`→Dossier
  findings (severity mapped). Preset via `BBOT_PRESET` (default
  `subdomain-enum`), passive via `BBOT_FLAGS="-rf passive"`. Coexists with the
  discrete PD modules — engines pick.
- **reNgine-style function modules** using tools in the image:
  - `urls` (katana) — crawl live sites for endpoints → `url` + `endpoint`.
  - `fuzzing` (ffuf) — directory/content discovery → `endpoint` + `finding`
    (auth-gated sensitive paths flagged). No wordlist is baked; set
    `FFUF_WORDLIST` to a mounted list (e.g. SecLists) or it skips.
  - `waf` (wafw00f) — WAF/CDN detection → `waf`.
- **reNgine-style engine presets** — `full-scan` (all discrete tools +
  crawl/fuzz/waf/nuclei), `bbot-recon` (BBOT-driven), `passive`, plus the
  original `default`. The declarative engine *is* reNgine's "scan engine"
  concept; order is resolved by the DAG.
- **Scope passthrough for non-host asset types** (`helpers/go/scope`) — `tech`,
  `waf`, `email`, `asn`, `bucket`, `screenshot` now ride along with the
  in-scope hosts they derive from instead of being host-matched and dropped.
  (This also fixes a latent bug where `tech` assets were silently scope-blocked.)

New asset types (`email`, `bucket`, `asn`, `endpoint`, `waf`, `screenshot`)
need no schema change — `assets.type` is free text, and ingest/normalize handle
any type.

Next: per-module config in the engine YAML (so an engine can set `BBOT_PRESET`
itself rather than via worker env), per-finding evidence view, run diffing.

---

### v0.1–v0.2 history

Built in v0.1: schema, the three-language pipeline, three modules (subfinder /
httpx / nuclei), declarative engines, orchestrator, web+worker skeleton, Compose.

Added in v0.2:

- **Real DAG resolver** (`helpers/py/plan.py`) — modules now execute in
  topological order derived from their `consumes`/`produces`, not engine file
  order. Ties break by file order; cycles are fatal. So `nuclei` can sit first
  in the file and still run last.
- **`portscan` module** (naabu) — emits `port` and `ip` assets. Defaults to a
  **connect scan** (`NAABU_SCAN_TYPE=c`) so it needs no privileges in a stock
  container; set `NAABU_SCAN_TYPE=s` with `CAP_NET_RAW` for SYN. naabu's own
  errors surface to the run console, and the module tolerates a naabu failure
  instead of aborting the engine.
- **Full ProjectDiscovery toolset** — the worker image now installs everything
  via `pdtm -install-all` (katana, dnsx, tlsx, mapcidr, asnmap, uncover, …) and
  puts it all on PATH, so a new module can reach for any PD tool with no
  Dockerfile change.
- **`screenshots` module** — delegates capture to **Snapshot** rather than
  bundling a headless browser. Set `SNAPSHOT_URL` (+ optional `SNAPSHOT_TOKEN`)
  to enable; it's disabled by default. The ingest contract it assumes is
  documented in `helpers/py/snapshot_client.py` — point me at Snapshot's real
  API and it's a one-file change to match exactly.
- **Websocket live output** — the worker streams every orchestrator line to a
  capped Redis list (`run:<id>:log`, for replay) and a pub/sub channel
  (`run:<id>:events`, live). The web tier's `/ws/runs/<id>` replays then
  follows, so scans stream to the UI.
- **Operator console** (`web/static/index.html`) — engagements, scope editor,
  run control, assets grouped by type, severity-sorted findings, and a live
  scan dock whose pipeline strip lights up as each module runs.

Next: per-finding evidence detail view (with Snapshot screenshots inline),
run history/diffing UI, engine editing from the UI, and MinIO-backed evidence
attachments feeding Dossier.

