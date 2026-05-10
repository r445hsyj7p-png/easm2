-- EASM Platform — PostgreSQL Initial Schema
-- Runs once on first container start

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Tenants
CREATE TABLE IF NOT EXISTS tenants (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT NOT NULL,
    domain      TEXT NOT NULL UNIQUE,
    active      BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Users
CREATE TABLE IF NOT EXISTS users (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email        TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role         TEXT NOT NULL DEFAULT 'analyst',
    active       BOOLEAN NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, email)
);

-- Findings
CREATE TABLE IF NOT EXISTS findings (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    severity      TEXT NOT NULL,
    category      TEXT NOT NULL,
    title         TEXT NOT NULL,
    affected_asset TEXT NOT NULL,
    description   TEXT,
    remediation   TEXT,
    cvss          NUMERIC(4,1),
    epss          TEXT,
    cve           TEXT,
    tool          TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'open',
    fingerprint   TEXT,
    kev           BOOLEAN DEFAULT false,
    age_days      INT DEFAULT 0,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, fingerprint)
);

-- Assets (subdomains / IPs)
CREATE TABLE IF NOT EXISTS assets (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    fqdn        TEXT,
    ip          TEXT,
    org         TEXT,
    asn         INT,
    ports       JSONB DEFAULT '[]',
    risk        TEXT,
    sources     JSONB DEFAULT '[]',
    takeover    BOOLEAN DEFAULT false,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, fqdn)
);

-- Scans
CREATE TABLE IF NOT EXISTS scans (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    status      TEXT NOT NULL DEFAULT 'pending',
    config      JSONB DEFAULT '{}',
    result      JSONB DEFAULT '{}',
    started_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_findings_tenant    ON findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status    ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_tool      ON findings(tool);
CREATE INDEX IF NOT EXISTS idx_assets_tenant      ON assets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scans_tenant       ON scans(tenant_id);
CREATE INDEX IF NOT EXISTS idx_findings_title_trgm ON findings USING gin(title gin_trgm_ops);
