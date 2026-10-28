#!/usr/bin/env python3
"""recce-snapshot-client: hand discovered URLs to Snapshot for capture.

Snapshot is the self-hosted tool that screenshots and indexes login pages, so
recce delegates capture to it rather than bundling a headless browser.

ASSUMED Snapshot ingest contract (adjust the endpoint/fields to match your
instance — or tell me the real API and I'll wire it exactly):

  POST {SNAPSHOT_URL}/api/captures
  Authorization: Bearer {SNAPSHOT_TOKEN}      (only if SNAPSHOT_TOKEN is set)
  Content-Type: application/json
  body: {"url": "<url>", "engagement": "<engagement-id>"}
  200 -> {"id": "<capture-id>", "image_url": "<url-to-image>"}

For each input URL, emits one screenshot asset:
  {"kind":"asset","type":"screenshot",
   "value": <image_url or capture id or source url>,
   "attrs":{"source_url": <url>, "snapshot_id": <id>}}

Uses only the stdlib (urllib) so the worker needs no extra Python deps.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engagement", default="")
    args = ap.parse_args()

    base = os.environ.get("SNAPSHOT_URL")
    if not base:
        sys.exit("snapshot_client: SNAPSHOT_URL not set")
    token = os.environ.get("SNAPSHOT_TOKEN")
    endpoint = base.rstrip("/") + "/api/captures"

    ok = err = 0
    for line in sys.stdin:
        url = line.strip()
        if not url:
            continue
        payload = json.dumps({"url": url, "engagement": args.engagement}).encode()
        req = urllib.request.Request(endpoint, data=payload,
                                     headers={"Content-Type": "application/json"})
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read() or b"{}")
            print(json.dumps({
                "kind": "asset", "type": "screenshot",
                "value": data.get("image_url") or data.get("id") or url,
                "attrs": {"source_url": url, "snapshot_id": data.get("id")},
            }))
            ok += 1
        except (urllib.error.URLError, ValueError, OSError) as e:
            sys.stderr.write(f"snapshot_client: {url}: {e}\n")
            err += 1
    sys.stderr.write(f"snapshot_client: captured={ok} errors={err}\n")


if __name__ == "__main__":
    main()
