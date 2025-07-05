"""add email confirmation token

Revision ID: addemailconfirmationtoken
Revises: f7e8d9c0a1b2
Create Date: 2025-07-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'addemailconfirmationtoken'
down_revision = 'f7e8d9c0a1b2'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.add_column('users', sa.Column('email_confirmation_token', sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'email_confirmation_token')
