"""add email confirmed flag

Revision ID: addemailconfirmedflag
Revises: addemailconfirmationtoken
Create Date: 2025-07-01 00:00:01.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'addemailconfirmedflag'
down_revision = 'addemailconfirmationtoken'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('users', sa.Column('email_confirmed', sa.Boolean(), nullable=False, server_default=sa.true()))


def downgrade() -> None:
    op.drop_column('users', 'email_confirmed')
