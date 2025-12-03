"""Merge multiple heads

Revision ID: 8312b7414491
Revises: 20251203_create_analytics_events, 2b3c4d5e6f7a
Create Date: 2025-12-03 23:14:29.004632

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8312b7414491'
down_revision = ('20251203_create_analytics_events', '2b3c4d5e6f7a')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
