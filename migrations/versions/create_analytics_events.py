"""create analytics events table

Revision ID: 20251203_create_analytics_events
Revises: fa2717c32bc6
Create Date: 2025-12-03

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20251203_create_analytics_events'
down_revision = 'fa2717c32bc6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'analytics_events',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column('user_id', sa.String(length=255), nullable=True),
        sa.Column('session_id', sa.String(length=255), nullable=True),
        sa.Column('event_type', sa.String(length=32), nullable=False),
        sa.Column('page_path', sa.Text(), nullable=False),
        sa.Column('element_id', sa.String(length=255), nullable=True),
        sa.Column('area', sa.String(length=255), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('ip_address', sa.String(length=64), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('NOW()'), nullable=False),
    )
    op.create_index('ix_analytics_events_created_at', 'analytics_events', ['created_at'])
    op.create_index('ix_analytics_events_event_type', 'analytics_events', ['event_type'])
    op.create_index('ix_analytics_events_page_path', 'analytics_events', ['page_path'])


def downgrade():
    op.drop_index('ix_analytics_events_page_path', table_name='analytics_events')
    op.drop_index('ix_analytics_events_event_type', table_name='analytics_events')
    op.drop_index('ix_analytics_events_created_at', table_name='analytics_events')
    op.drop_table('analytics_events')
