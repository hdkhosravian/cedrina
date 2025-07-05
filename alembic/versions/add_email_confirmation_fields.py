"""add email confirmation fields

Revision ID: add_email_confirmation_fields
Revises: 21b29c875b37
Create Date: 2025-01-27 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_email_confirmation_fields'
down_revision = '21b29c875b37'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add email confirmation fields to users table
    op.add_column('users', sa.Column('email_confirmation_token', sa.String(length=64), nullable=True))
    op.add_column('users', sa.Column('email_confirmed', sa.Boolean(), nullable=False, server_default='false'))
    
    # Create index on email_confirmation_token for efficient lookups
    op.create_index(op.f('ix_users_email_confirmation_token'), 'users', ['email_confirmation_token'], unique=False)


def downgrade() -> None:
    # Remove index
    op.drop_index(op.f('ix_users_email_confirmation_token'), table_name='users')
    
    # Remove columns
    op.drop_column('users', 'email_confirmed')
    op.drop_column('users', 'email_confirmation_token') 