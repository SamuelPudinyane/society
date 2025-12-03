"""
Add analytics_events table

Revision ID: 1a2b3c4d5e6f
Revises: fa2717c32bc6
Create Date: 2025-12-03
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1a2b3c4d5e6f'
down_revision = 'fa2717c32bc6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'analytics_events',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('user_id', sa.String(255), nullable=True, index=True),
        sa.Column('session_id', sa.String(64), nullable=True, index=True),
        sa.Column('event_type', sa.String(32), nullable=False),
        sa.Column('page_path', sa.String(512), nullable=False, index=True),
        sa.Column('element_id', sa.String(256), nullable=True),
        sa.Column('area', sa.String(256), nullable=True),
        sa.Column('duration_ms', sa.Integer, nullable=True),
        sa.Column('ip_address', sa.String(64), nullable=True),
        sa.Column('user_agent', sa.Text, nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_analytics_events_event_type', 'analytics_events', ['event_type'])


def downgrade():
    op.drop_index('ix_analytics_events_event_type', table_name='analytics_events')
    op.drop_table('analytics_events')
