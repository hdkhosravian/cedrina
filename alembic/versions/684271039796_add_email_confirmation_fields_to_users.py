"""add_email_confirmation_fields_to_users

Revision ID: 684271039796
Revises: 93ecdab1abcb
Create Date: 2025-07-05 11:37:06.450674

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '684271039796'
down_revision: Union[str, None] = '93ecdab1abcb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
