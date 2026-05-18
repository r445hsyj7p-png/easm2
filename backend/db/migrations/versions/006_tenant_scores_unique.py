"""Add UNIQUE constraint on tenant_scores.tenant_id for ON CONFLICT upsert

Revision ID: 006
Revises: 005
Create Date: 2026-05-18
"""
from alembic import op

revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DELETE FROM tenant_scores ts
        WHERE id NOT IN (
            SELECT DISTINCT ON (tenant_id) id
            FROM tenant_scores
            ORDER BY tenant_id, recorded_at DESC
        );
    """)

    op.execute("""
        ALTER TABLE tenant_scores
          ADD CONSTRAINT uq_tenant_scores_tenant_id
          UNIQUE (tenant_id);
    """)


def downgrade() -> None:
    op.execute(
        "ALTER TABLE tenant_scores DROP CONSTRAINT IF EXISTS uq_tenant_scores_tenant_id;"
    )
