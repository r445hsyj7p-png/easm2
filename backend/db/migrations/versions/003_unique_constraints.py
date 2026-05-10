"""Add unique constraints to assets and mcp_servers for correct ON CONFLICT upserts

Revision ID: 003
Revises: 002
Create Date: 2026-05-10
"""
from alembic import op

revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE assets
          ADD CONSTRAINT uq_assets_tenant_fqdn_ip
          UNIQUE (tenant_id, fqdn, ip);
    """)

    op.execute("""
        ALTER TABLE mcp_servers
          ADD CONSTRAINT uq_mcp_tenant_url_port
          UNIQUE (tenant_id, url, port);
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE assets DROP CONSTRAINT IF EXISTS uq_assets_tenant_fqdn_ip;")
    op.execute("ALTER TABLE mcp_servers DROP CONSTRAINT IF EXISTS uq_mcp_tenant_url_port;")
