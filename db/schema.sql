-- recce schema  (PostgreSQL 14+)
-- The two load-bearing tables are `assets` and `findings`.
-- findings is shaped to be Dossier-native: report generation is a query here,
-- not an import/export handshake.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()

-- ---------------------------------------------------------------------------
-- Engagements & scope
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS engagements (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    status      TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active','paused','closed')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Scope is a first-class gate, enforced in the worker (recce-scope), never
-- only in the UI. include rules seed recon; exclude rules hard-drop.
CREATE TABLE IF NOT EXISTS scope_rules (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id  UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    kind           TEXT NOT NULL CHECK (kind IN ('include','exclude')),
    pattern_type   TEXT NOT NULL CHECK (pattern_type IN ('domain','cidr','regex')),
    value          TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (engagement_id, kind, pattern_type, value)
);

-- ---------------------------------------------------------------------------
-- Runs (a scan execution of one engine) and per-module bookkeeping
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS runs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id  UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    engine         TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'queued'
                     CHECK (status IN ('queued','running','done','failed','cancelled')),
    started_at     TIMESTAMPTZ,
    finished_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS module_runs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id      UUID NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    module      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'queued'
                  CHECK (status IN ('queued','running','done','failed','skipped')),
    stats       JSONB NOT NULL DEFAULT '{}'::jsonb,
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

-- ---------------------------------------------------------------------------
-- Assets  (the normalized store)
-- Uniqueness on (engagement, type, value) gives dedup for free; provenance
-- (source_module, run, first/last_seen) gives run-to-run diffing.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assets (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id  UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    type           TEXT NOT NULL,          -- domain|subdomain|ip|port|service|url|tech|cert|endpoint
    value          TEXT NOT NULL,
    attrs          JSONB NOT NULL DEFAULT '{}'::jsonb,
    source_module  TEXT,
    first_run_id   UUID REFERENCES runs(id) ON DELETE SET NULL,
    last_run_id    UUID REFERENCES runs(id) ON DELETE SET NULL,
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (engagement_id, type, value)
);
CREATE INDEX IF NOT EXISTS assets_eng_type_idx ON assets (engagement_id, type);
CREATE INDEX IF NOT EXISTS assets_attrs_gin    ON assets USING gin (attrs);
CREATE INDEX IF NOT EXISTS assets_lastseen_idx ON assets (engagement_id, last_seen);

-- ---------------------------------------------------------------------------
-- Findings  (Dossier-native)
-- dedup_key collapses re-discoveries across runs; the status workflow matches
-- a pentest reporting lifecycle so Dossier reads this table directly.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id  UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    run_id         UUID REFERENCES runs(id) ON DELETE SET NULL,
    asset_id       UUID REFERENCES assets(id) ON DELETE SET NULL,

    title          TEXT NOT NULL,
    severity       TEXT NOT NULL DEFAULT 'info'
                     CHECK (severity IN ('info','low','medium','high','critical')),
    cvss_score     NUMERIC(3,1),
    cvss_vector    TEXT,
    cwe            TEXT,                    -- e.g. CWE-79
    description    TEXT,
    evidence       JSONB NOT NULL DEFAULT '[]'::jsonb,  -- ordered evidence blocks
    remediation    TEXT,
    refs           JSONB NOT NULL DEFAULT '[]'::jsonb,

    status         TEXT NOT NULL DEFAULT 'open'
                     CHECK (status IN ('open','triaged','confirmed','remediated','false_positive','accepted')),
    source_module  TEXT,
    dedup_key      TEXT NOT NULL,

    -- CVE intelligence (CVEngine-style prioritization). Populated by the
    -- enrich_cves pass from CISA KEV + FIRST EPSS for findings that carry a
    -- CVE id. priority is the fire/smoke/ice tier.
    cve_id         TEXT,
    kev            BOOLEAN NOT NULL DEFAULT false,   -- CISA Known Exploited
    epss           NUMERIC(6,5),                     -- FIRST EPSS probability 0..1
    priority       TEXT CHECK (priority IN ('fire','smoke','ice')),

    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (engagement_id, dedup_key)
);
CREATE INDEX IF NOT EXISTS findings_eng_sev_idx ON findings (engagement_id, severity);
CREATE INDEX IF NOT EXISTS findings_status_idx  ON findings (engagement_id, status);
CREATE INDEX IF NOT EXISTS findings_priority_idx ON findings (engagement_id, priority);

-- Migration for databases created before the CVE-intel columns existed. These
-- are no-ops on a fresh init (the columns are already in CREATE TABLE above)
-- and safe to re-run. Existing deployments: this block adds the columns.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cve_id   TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS kev      BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS epss     NUMERIC(6,5);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS priority TEXT;

-- Convenience view: newest assets first, with age. Handy for the UI and for
-- the "what appeared since last run" continuous-monitoring diff.
CREATE OR REPLACE VIEW asset_feed AS
SELECT a.*, (now() - a.first_seen) AS age
FROM assets a
ORDER BY a.first_seen DESC;
