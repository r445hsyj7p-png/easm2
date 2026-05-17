"""Add ip_ranges/panos to domains; add settings JSONB to tenants

Revision ID: 005
Revises: 004
Create Date: 2026-05-17
"""
from alembic import op

revision = '005'
down_revision = '004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE domains
          ADD COLUMN IF NOT EXISTS ip_ranges     TEXT[]    DEFAULT '{}',
          ADD COLUMN IF NOT EXISTS last_scan     TIMESTAMPTZ,
          ADD COLUMN IF NOT EXISTS findings_count INTEGER  DEFAULT 0,
          ADD COLUMN IF NOT EXISTS risk_score    INTEGER,
          ADD COLUMN IF NOT EXISTS panos_version TEXT;
    """)
    op.execute("""
        ALTER TABLE tenants
          ADD COLUMN IF NOT EXISTS settings JSONB DEFAULT '{}';
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TABLE domains
          DROP COLUMN IF EXISTS ip_ranges,
          DROP COLUMN IF EXISTS last_scan,
          DROP COLUMN IF EXISTS findings_count,
          DROP COLUMN IF EXISTS risk_score,
          DROP COLUMN IF EXISTS panos_version;
    """)
    op.execute("ALTER TABLE tenants DROP COLUMN IF EXISTS settings;")
