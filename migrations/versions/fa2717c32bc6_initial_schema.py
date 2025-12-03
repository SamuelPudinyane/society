"""initial schema

Revision ID: fa2717c32bc6
Revises: 
Create Date: 2025-12-03 01:43:35.106160

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'fa2717c32bc6'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Create core tables for Postgres
    op.create_table(
        'Users',
        sa.Column('user_id', sa.String(length=255), nullable=False),
        sa.Column('first_name', sa.String(length=25), nullable=False),
        sa.Column('last_name', sa.String(length=25), nullable=False),
        sa.Column('email', sa.String(length=120), nullable=False),
        sa.Column('contact_number', sa.String(length=15), nullable=False),
        sa.Column('occupation', sa.String(length=50), nullable=False),
        sa.Column('gender', sa.String(length=6), nullable=False),
        sa.Column('date_of_birth', sa.Date(), nullable=False),
        sa.Column('address', sa.String(length=200), nullable=False),
        sa.Column('postal_code', sa.String(length=4), nullable=False),
        sa.Column('role', sa.String(length=15), nullable=False),
        sa.Column('password', sa.String(length=255), nullable=True),
        sa.Column('active', sa.Boolean(), server_default=sa.text('false'), nullable=False),
        sa.Column('verified', sa.Boolean(), server_default=sa.text('false'), nullable=False),
        sa.PrimaryKeyConstraint('user_id')
    )

    op.create_index('ix_users_email', 'Users', ['email'], unique=True)

    op.create_table(
        'user_profile',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=255), nullable=False),
        sa.Column('bio', sa.Text(), nullable=True),
        sa.Column('avatar', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('NOW()')), 
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('NOW()')),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['Users.user_id'], ondelete='CASCADE')
    )

    op.create_table(
        'user_token',
        sa.Column('token', sa.String(length=72), nullable=False),
        sa.Column('salt', sa.String(length=255), nullable=True),
        sa.Column('expire', sa.Boolean(), server_default=sa.text('false'), nullable=False),
        sa.Column('user_id', sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint('token'),
        sa.ForeignKeyConstraint(['user_id'], ['Users.user_id'], ondelete='CASCADE')
    )

    op.create_table(
        'copies',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column('id_copy', sa.String(), nullable=True),
        sa.Column('certificate', sa.String(), nullable=True),
        sa.Column('user_id', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['Users.user_id'], ondelete='CASCADE')
    )


def downgrade():
    # Drop in reverse order to satisfy FKs
    op.drop_table('copies')
    op.drop_table('user_token')
    op.drop_table('user_profile')
    op.drop_index('ix_users_email', table_name='Users')
    op.drop_table('Users')
