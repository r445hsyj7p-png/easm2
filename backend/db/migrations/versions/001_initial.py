"""Initial schema — production-ready

Revision ID: 001
Revises: 
Create Date: 2026-05-10
"""
from alembic import op
import sqlalchemy as sa

revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Enable extensions
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm;")
    op.execute("CREATE EXTENSION IF NOT EXISTS btree_gin;")

    # tenants
    op.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            id         TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            name       TEXT NOT NULL,
            slug       TEXT UNIQUE NOT NULL,
            status     TEXT DEFAULT 'active',
            primary_email TEXT,
            company_name  TEXT,
            sla_level  TEXT DEFAULT 'silver',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)

    # users
    op.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            tenant_id     TEXT REFERENCES tenants(id) ON DELETE CASCADE,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL DEFAULT '',
            pw_hash       TEXT,
            full_name     TEXT,
            role          TEXT DEFAULT 'mssp_admin',
            role_v2       TEXT DEFAULT 'mssp_admin',
            is_active     BOOLEAN DEFAULT TRUE,
            last_login    TIMESTAMPTZ,
            created_at    TIMESTAMPTZ DEFAULT NOW()
        )
    """)

    # domains
    op.execute("""
        CREATE TABLE IF NOT EXISTS domains (
            id        TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            domain    TEXT NOT NULL,
            fqdn      TEXT,
            status    TEXT DEFAULT 'active',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(tenant_id, domain)
        )
    """)

    # scan_jobs
    op.execute("""
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id                 TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            tenant_id          TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            target_domain_id   TEXT,
            target_ip_range_id TEXT,
            scan_type          TEXT DEFAULT 'full',
            status             TEXT DEFAULT 'pending',
            triggered_by       TEXT DEFAULT 'manual',
            findings_count     JSONB DEFAULT '{}',
            risk_score_before  INTEGER,
            risk_score_after   INTEGER,
            duration_seconds   INTEGER,
            celery_task_id     TEXT,
            error_message      TEXT,
            raw_results        JSONB,
            scheduled_for      TIMESTAMPTZ,
            created_at         TIMESTAMPTZ DEFAULT NOW(),
            started_at         TIMESTAMPTZ,
            completed_at       TIMESTAMPTZ
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_scanjobs_tenant ON scan_jobs(tenant_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_scanjobs_status ON scan_jobs(status)")

    # findings (legacy — kept for worker compatibility)
    op.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            scan_job_id TEXT,
            severity    TEXT,
            category    TEXT,
            title       TEXT NOT NULL,
            asset       TEXT,
            cve_id      TEXT,
            cvss_score  NUMERIC(4,1),
            epss_score  NUMERIC(6,4),
            cisa_kev    BOOLEAN DEFAULT FALSE,
            tool        TEXT,
            description TEXT,
            remediation TEXT,
            status      TEXT DEFAULT 'open',
            ticket_ref  TEXT,
            fingerprint TEXT UNIQUE,
            first_seen_at TIMESTAMPTZ DEFAULT NOW(),
            last_seen_at  TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_findings_tenant ON findings(tenant_id)")

    # findings_v2 (production API table)
    op.execute("""
        CREATE TABLE IF NOT EXISTS findings_v2 (
            id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            scan_job_id TEXT,
            sev         TEXT NOT NULL DEFAULT 'INFO',
            cat         TEXT NOT NULL DEFAULT 'exposure',
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
            "desc"      TEXT,
            fix         TEXT,
            fingerprint TEXT UNIQUE,
            first_seen  TIMESTAMPTZ DEFAULT NOW(),
            last_seen   TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_findings2_tenant ON findings_v2(tenant_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_findings2_sev    ON findings_v2(tenant_id, sev)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_findings2_status ON findings_v2(tenant_id, status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_findings2_kev    ON findings_v2(tenant_id, kev) WHERE kev = TRUE")
    op.execute("CREATE INDEX IF NOT EXISTS ix_findings2_first  ON findings_v2(tenant_id, first_seen DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_findings2_title_trgm ON findings_v2 USING GIN (title gin_trgm_ops)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_findings2_asset_trgm ON findings_v2 USING GIN (asset gin_trgm_ops)")

    # assets
    op.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id         TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            fqdn       TEXT,
            ip         INET,
            org        TEXT,
            asn        INTEGER,
            ports      INTEGER[],
            risk       TEXT DEFAULT 'LOW',
            sources    TEXT[],
            takeover   BOOLEAN DEFAULT FALSE,
            first_seen TIMESTAMPTZ DEFAULT NOW(),
            last_seen  TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_assets_tenant ON assets(tenant_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_assets_risk   ON assets(tenant_id, risk)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_assets_fqdn_trgm ON assets USING GIN (fqdn gin_trgm_ops)")

    # mcp_servers
    op.execute("""
        CREATE TABLE IF NOT EXISTS mcp_servers (
            id                TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            tenant_id         TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            url               TEXT,
            port              INTEGER,
            auth              BOOLEAN DEFAULT FALSE,
            tools             TEXT[],
            server_info       TEXT,
            cve               TEXT,
            risk              TEXT DEFAULT 'CRITICAL',
            injection         BOOLEAN DEFAULT FALSE,
            inspection_active BOOLEAN DEFAULT FALSE,
            first_seen        TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_mcp_tenant ON mcp_servers(tenant_id)")

    # intel_snapshots
    op.execute("""
        CREATE TABLE IF NOT EXISTS intel_snapshots (
            id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            scan_job_id TEXT,
            data        JSONB NOT NULL DEFAULT '{}',
            created_at  TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_intel_tenant ON intel_snapshots(tenant_id, created_at DESC)")

    # tenant_scores
    op.execute("""
        CREATE TABLE IF NOT EXISTS tenant_scores (
            id               TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            tenant_id        TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            score            INTEGER NOT NULL DEFAULT 100,
            grade            TEXT DEFAULT 'A',
            findings_summary JSONB DEFAULT '{}',
            asset_counts     JSONB DEFAULT '{}',
            tool_stats       JSONB DEFAULT '{}',
            recorded_at      TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_scores_tenant ON tenant_scores(tenant_id, recorded_at DESC)")


def downgrade() -> None:
    for tbl in ["tenant_scores","intel_snapshots","mcp_servers",
                "assets","findings_v2","findings","scan_jobs","domains","users","tenants"]:
        op.execute(f"DROP TABLE IF EXISTS {tbl} CASCADE")
