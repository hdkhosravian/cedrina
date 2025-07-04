"""add_email_confirmation_fields

Revision ID: ec964d9b5e69
Revises: 93ecdab1abcb
Create Date: 2025-07-04 16:31:13.131987

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ec964d9b5e69'
down_revision: Union[str, None] = '93ecdab1abcb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add email confirmation fields to users table."""
    # Add email confirmation fields
    op.add_column('users', sa.Column('email_confirmed', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.add_column('users', sa.Column('email_confirmation_token', sa.String(length=64), nullable=True))
    op.add_column('users', sa.Column('email_confirmed_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    """Remove email confirmation fields from users table."""
    # Remove email confirmation fields
    op.drop_column('users', 'email_confirmed_at')
    op.drop_column('users', 'email_confirmation_token')
    op.drop_column('users', 'email_confirmed')
