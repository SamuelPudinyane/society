"""
Create core application tables (Users, user_profile, user_token, copies)

Revision ID: 2b3c4d5e6f7a
Revises: 1a2b3c4d5e6f
Create Date: 2025-12-03
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2b3c4d5e6f7a'
down_revision = '1a2b3c4d5e6f'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)

    # Users
    if not insp.has_table('Users'):
        op.create_table(
            'Users',
            sa.Column('user_id', sa.String(length=255), primary_key=True, nullable=False),
            sa.Column('first_name', sa.String(length=25), nullable=False),
            sa.Column('last_name', sa.String(length=25), nullable=False),
            sa.Column('email', sa.String(length=120), nullable=False, unique=True),
            sa.Column('contact_number', sa.String(length=15), nullable=False),
            sa.Column('occupation', sa.String(length=50), nullable=False),
            sa.Column('gender', sa.String(length=6), nullable=False),
            sa.Column('date_of_birth', sa.Date(), nullable=False),
            sa.Column('address', sa.String(length=200), nullable=False),
            sa.Column('postal_code', sa.String(length=10), nullable=False),
            sa.Column('role', sa.String(length=15), nullable=False),
            sa.Column('password', sa.String(length=128), nullable=False),
            sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.text('false')),
            sa.Column('verified', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        )

    # user_profile
    if not insp.has_table('user_profile'):
        op.create_table(
            'user_profile',
            sa.Column('user_id', sa.String(length=255), sa.ForeignKey('Users.user_id'), primary_key=True, nullable=False),
            sa.Column('bio', sa.Text(), nullable=True),
            sa.Column('avatar', sa.String(length=255), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )

    # user_token
    if not insp.has_table('user_token'):
        op.create_table(
            'user_token',
            sa.Column('token', sa.String(length=72), primary_key=True, nullable=False),
            sa.Column('salt', sa.String(length=20), nullable=True),
            sa.Column('expire', sa.Boolean(), nullable=False, server_default=sa.text('false')),
            sa.Column('user_id', sa.String(length=255), sa.ForeignKey('Users.user_id'), nullable=False),
        )
        op.create_index('ix_user_token_user_id', 'user_token', ['user_id'])

    # copies
    if not insp.has_table('copies'):
        op.create_table(
            'copies',
            sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
            sa.Column('id_copy', sa.Text(), nullable=True),
            sa.Column('certificate', sa.Text(), nullable=True),
            sa.Column('user_id', sa.String(length=255), sa.ForeignKey('Users.user_id'), nullable=False),
        )
        op.create_index('ix_copies_user_id', 'copies', ['user_id'])


def downgrade():
    op.drop_index('ix_copies_user_id', table_name='copies')
    op.drop_table('copies')
    op.drop_index('ix_user_token_user_id', table_name='user_token')
    op.drop_table('user_token')
    op.drop_table('user_profile')
    op.drop_table('Users')
