# ---- stage 1: build the Go helpers (static, stdlib-only) -------------------
FROM golang:1.24-alpine AS gobuild
WORKDIR /src
COPY helpers/go/ ./
RUN CGO_ENABLED=0 go build -o /out/recce-normalize ./normalize \
 && CGO_ENABLED=0 go build -o /out/recce-scope     ./scope

# ---- stage 2: fetch the ProjectDiscovery recon tools via pdtm -------------
# pdtm downloads PREBUILT release binaries instead of compiling from source,
# so we sidestep the go-version treadmill (e.g. httpx now needs go >= 1.26).
#
# This stage MUST use the same libc as the runtime. Most PD tools are static
# Go binaries and run anywhere, but naabu links libpcap dynamically — a
# musl (alpine) naabu can't run on a glibc (debian) runtime ("cannot execute:
# required file not found" = missing ELF interpreter). So we build on Debian.
FROM golang:1.25-bookworm AS tools
# GOTOOLCHAIN=auto lets `go install` download a newer Go toolchain on demand
# when a tool raises its floor (pdtm now needs >= 1.25, and it will keep
# moving), so this stage self-heals instead of failing with "requires go >= X".
ENV GOTOOLCHAIN=auto
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates libpcap-dev \
 && rm -rf /var/lib/apt/lists/*
RUN go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
# Install the whole ProjectDiscovery toolset (subfinder, httpx, naabu, nuclei,
# katana, dnsx, tlsx, mapcidr, asnmap, uncover, ...) so new modules can reach
# for any of them without a Dockerfile change.
RUN pdtm -no-color -disable-update-check -install-all \
 && ls -la /root/.pdtm/go/bin
# install-all can silently skip naabu; ensure it explicitly, then verify it
# actually RUNS (fail the build here on any libc/libpcap problem instead of
# discovering it mid-scan). No `|| true` — a broken naabu must stop the build.
RUN test -x /root/.pdtm/go/bin/naabu || pdtm -no-color -install naabu
RUN /root/.pdtm/go/bin/naabu -version

# ffuf (directory fuzzing) isn't a ProjectDiscovery tool, so pdtm doesn't carry
# it — install it here with go (GOTOOLCHAIN=auto handles its Go floor). GOPATH
# is /go in this image, so the binary lands at /go/bin/ffuf.
RUN go install github.com/ffuf/ffuf/v2@latest \
 && /go/bin/ffuf -V

# gowitness (headless screenshots, `gowitness` module) — a Go tool.
RUN go install github.com/sensepost/gowitness@latest \
 && /go/bin/gowitness version

# ---- stage 3: runtime ------------------------------------------------------
# Pinned to bookworm so `libpcap0.8` is the correct package name (trixie
# renamed it to libpcap0.8t64), which naabu links against.
FROM python:3.12-slim-bookworm

# Runtime system deps:
#  nmap      — the `nmap` module (service/version + vulners CVE scan). CORE.
#  chromium  — headless browser gowitness drives for screenshots.
#  libpcap   — naabu's runtime lib.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash ca-certificates libpcap0.8 git curl nmap chromium \
 && rm -rf /var/lib/apt/lists/*

# vulners NSE script for nmap CVE lookup, into nmap's script dir, then rebuild
# the script DB. Core to the nmap module's vuln scan, so verify it landed.
RUN NSEDIR="$(nmap --dump-flags 2>/dev/null; echo /usr/share/nmap/scripts)"; \
    NSEDIR=/usr/share/nmap/scripts; \
    curl -fsSL https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse \
      -o "$NSEDIR/vulners.nse" \
 && nmap --script-updatedb >/dev/null 2>&1 \
 && nmap --script-help vulners >/dev/null 2>&1 \
 && echo "nmap vulners NSE installed" \
 || echo "WARN: vulners NSE install failed; nmap module runs service-scan only"

WORKDIR /opt/recce

# Go helpers
COPY --from=gobuild /out/recce-normalize /opt/recce/bin/recce-normalize
COPY --from=gobuild /out/recce-scope     /opt/recce/bin/recce-scope
# The entire ProjectDiscovery toolset onto PATH in one shot.
COPY --from=tools   /root/.pdtm/go/bin/  /usr/local/bin/
# ffuf (fuzzing module), built in the tools stage.
COPY --from=tools   /go/bin/ffuf         /usr/local/bin/ffuf
# gowitness (screenshots module), built in the tools stage.
COPY --from=tools   /go/bin/gowitness    /usr/local/bin/gowitness
# naabu links libpcap (installed above). It connect-scans without privileges;
# for SYN scans give the worker CAP_NET_RAW in docker-compose.

# Python helper deps (ingest / engagement lifecycle) and the RQ worker
COPY helpers/py/requirements.txt helpers/py/requirements.txt
RUN pip install --no-cache-dir -r helpers/py/requirements.txt

# BBOT (recursive recon engine, `bbot` module) and wafw00f (WAF detection,
# `waf` module) are Python tools. BBOT manages its own sub-tools at first run
# via `-y`. This is a heavy layer, so it sits on its own for build caching.
RUN pip install --no-cache-dir bbot wafw00f \
 && bbot --version \
 && wafw00f --version

# aardwolf (RDP client, `rdp` module NLA probe) — Python. Best-effort.
RUN pip install --no-cache-dir aardwolf \
 && echo "aardwolf installed" \
 || echo "WARN: aardwolf install failed; rdp module runs exposure-only"

# node2shell-scanner (`node2shell` module, CVE-2026-111497). Cloned to
# /opt/node2shell; the module invokes python3 /opt/node2shell/scanner.py.
RUN git clone --depth 1 https://github.com/assetnote/node2shell-scanner /opt/node2shell \
 && pip install --no-cache-dir -r /opt/node2shell/requirements.txt \
 && echo "node2shell-scanner installed" \
 || echo "WARN: node2shell-scanner install failed; node2shell module skips"

# WPScan (`wpscan` module) — a Ruby gem. Needs a toolchain to build native
# extensions. Best-effort: a gem build failure must not brick the image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ruby ruby-dev build-essential libcurl4-openssl-dev \
 && gem install wpscan --no-document \
 && wpscan --version \
 && apt-get purge -y ruby-dev build-essential && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* \
 && echo "wpscan installed" \
 || echo "WARN: wpscan install failed; wpscan module skips"

# The bash core + helpers
COPY modules/      modules/
COPY orchestrator/ orchestrator/
COPY engines/      engines/
COPY helpers/      helpers/
COPY web/worker.py web/worker.py
RUN chmod +x modules/*.sh orchestrator/*.sh bin/* || true

ENV RECCE_HOME=/opt/recce \
    RECCE_BIN=/opt/recce/bin \
    PATH="/opt/recce/bin:${PATH}"

# Bake the nuclei templates into the image. NOTE: do NOT pass -duc here — it
# suppresses the very download we want, leaving the image template-less and the
# scan failing with "no templates provided for scan". Then verify a non-empty
# template directory actually landed, so a failed fetch stops the build here
# instead of surfacing mid-scan.
RUN nuclei -update-templates \
 && found=""; \
    for d in /root/nuclei-templates /root/.config/nuclei-templates /root/.local/nuclei-templates; do \
      [ -d "$d" ] && [ -n "$(ls -A "$d" 2>/dev/null)" ] && found="$d" && break; \
    done; \
    [ -n "$found" ] && echo "nuclei templates baked at $found" \
      || { echo "FATAL: nuclei templates not present after update"; exit 1; }

WORKDIR /opt/recce/web
CMD ["rq", "worker", "recce", "--url", "redis://redis:6379/0"]
