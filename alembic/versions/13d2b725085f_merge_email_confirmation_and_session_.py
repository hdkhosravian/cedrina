"""merge email confirmation and session activity tracking heads

Revision ID: 13d2b725085f
Revises: addemailconfirmedflag, 93ecdab1abcb
Create Date: 2025-07-05 19:41:11.082481

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '13d2b725085f'
down_revision: Union[str, None] = ('addemailconfirmedflag', '93ecdab1abcb')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
