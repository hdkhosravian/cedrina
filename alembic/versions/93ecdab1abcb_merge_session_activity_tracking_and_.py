"""merge session activity tracking and other head

Revision ID: 93ecdab1abcb
Revises: add_session_activity_tracking, f7e8d9c0a1b2
Create Date: 2025-06-30 22:18:09.981511

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '93ecdab1abcb'
down_revision: Union[str, None] = ('add_session_activity_tracking', 'f7e8d9c0a1b2')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
