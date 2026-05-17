"""Add technologies column to assets

Revision ID: 004
Revises: 003
"""
from alembic import op

revision = '004'
down_revision = '003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE assets
          ADD COLUMN IF NOT EXISTS technologies JSONB NOT NULL DEFAULT '[]';
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_assets_technologies
          ON assets USING GIN (technologies);
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_assets_technologies;")
    op.execute("ALTER TABLE assets DROP COLUMN IF EXISTS technologies;")
