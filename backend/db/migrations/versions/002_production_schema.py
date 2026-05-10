"""Production schema — full tables matching the API field names

Revision ID: 002
Revises: 001
Create Date: 2026-05-10
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── users: add missing columns ────────────────────────────────────────────
    op.execute("""
        ALTER TABLE users
          ADD COLUMN IF NOT EXISTS full_name    TEXT,
          ADD COLUMN IF NOT EXISTS role_v2      TEXT DEFAULT 'mssp_admin',
          ADD COLUMN IF NOT EXISTS pw_hash      TEXT,
          ADD COLUMN IF NOT EXISTS is_active    BOOLEAN DEFAULT TRUE,
          ADD COLUMN IF NOT EXISTS last_login   TIMESTAMPTZ;
    """)

    # ── assets (discovered subdomains / IPs) ──────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            fqdn        TEXT,
            ip          INET,
            org         TEXT,
            asn         INTEGER,
            ports       INTEGER[],
            risk        TEXT DEFAULT 'LOW',
            sources     TEXT[],
            takeover    BOOLEAN DEFAULT FALSE,
            first_seen  TIMESTAMPTZ DEFAULT NOW(),
            last_seen   TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS ix_assets_tenant ON assets(tenant_id);
        CREATE INDEX IF NOT EXISTS ix_assets_risk   ON assets(tenant_id, risk);
    """)

    # ── findings: full schema ─────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS findings_v2 (
            id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            scan_job_id TEXT,
            sev         TEXT NOT NULL,
            cat         TEXT NOT NULL,
            tool        TEXT,
            title       TEXT NOT NULL,
            asset       TEXT,
            status      TEXT DEFAULT 'open',
            ticket_ref  TEXT,
            cve         TEXT,
            cvss        FLOAT,
            epss        TEXT,
            kev         BOOLEAN DEFAULT FALSE,
            age         INTEGER DEFAULT 0,
            desc        TEXT,
            fix         TEXT,
            fingerprint TEXT UNIQUE,
            first_seen  TIMESTAMPTZ DEFAULT NOW(),
            last_seen   TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS ix_findings2_tenant   ON findings_v2(tenant_id);
        CREATE INDEX IF NOT EXISTS ix_findings2_sev      ON findings_v2(tenant_id, sev);
        CREATE INDEX IF NOT EXISTS ix_findings2_status   ON findings_v2(tenant_id, status);
        CREATE INDEX IF NOT EXISTS ix_findings2_cat      ON findings_v2(tenant_id, cat);
        CREATE INDEX IF NOT EXISTS ix_findings2_first    ON findings_v2(tenant_id, first_seen DESC);
        CREATE INDEX IF NOT EXISTS ix_findings2_kev      ON findings_v2(tenant_id, kev) WHERE kev = TRUE;
    """)

    # ── mcp_servers ───────────────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS mcp_servers (
            id                 TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            tenant_id          TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            url                TEXT,
            port               INTEGER,
            auth               BOOLEAN DEFAULT FALSE,
            tools              TEXT[],
            server_info        TEXT,
            cve                TEXT,
            risk               TEXT DEFAULT 'CRITICAL',
            injection          BOOLEAN DEFAULT FALSE,
            inspection_active  BOOLEAN DEFAULT FALSE,
            first_seen         TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS ix_mcp_tenant ON mcp_servers(tenant_id);
    """)

    # ── intel (hosting analysis, geo, fqdn) ───────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS intel_snapshots (
            id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            scan_job_id TEXT,
            data        JSONB NOT NULL,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS ix_intel_tenant ON intel_snapshots(tenant_id, created_at DESC);
    """)

    # ── tenant_scores (risk score history) ───────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS tenant_scores (
            id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            score       INTEGER NOT NULL,
            grade       TEXT,
            findings_summary JSONB,
            asset_counts     JSONB,
            tool_stats       JSONB,
            recorded_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS ix_scores_tenant ON tenant_scores(tenant_id, recorded_at DESC);
    """)

    # ── pg_trgm for full-text search ──────────────────────────────────────────
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm;")
    op.execute("CREATE EXTENSION IF NOT EXISTS btree_gin;")
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_findings2_title_trgm
          ON findings_v2 USING GIN (title gin_trgm_ops);
        CREATE INDEX IF NOT EXISTS ix_findings2_asset_trgm
          ON findings_v2 USING GIN (asset gin_trgm_ops);
        CREATE INDEX IF NOT EXISTS ix_assets_fqdn_trgm
          ON assets USING GIN (fqdn gin_trgm_ops);
        CREATE INDEX IF NOT EXISTS ix_assets_org_trgm
          ON assets USING GIN (org gin_trgm_ops);
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS intel_snapshots;")
    op.execute("DROP TABLE IF EXISTS mcp_servers;")
    op.execute("DROP TABLE IF EXISTS findings_v2;")
    op.execute("DROP TABLE IF EXISTS assets;")
    op.execute("DROP TABLE IF EXISTS tenant_scores;")
