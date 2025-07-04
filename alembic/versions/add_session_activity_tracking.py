"""Add session activity tracking

Revision ID: add_session_activity_tracking
Revises: 21b29c875b37
Create Date: 2025-01-27 10:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'add_session_activity_tracking'
down_revision: Union[str, None] = '21b29c875b37'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add last_activity_at field to sessions table."""
    # Add last_activity_at column with default value
    op.add_column('sessions', sa.Column('last_activity_at', sa.DateTime(), nullable=True))
    
    # Set default value for existing sessions (use created_at as initial last_activity_at)
    op.execute("UPDATE sessions SET last_activity_at = created_at WHERE last_activity_at IS NULL")
    
    # Make the column not nullable after setting default values
    op.alter_column('sessions', 'last_activity_at', nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'))
    
    # Add index for inactivity-based cleanup
    op.create_index('ix_sessions_last_activity_at', 'sessions', ['last_activity_at'], unique=False)


def downgrade() -> None:
    """Remove last_activity_at field from sessions table."""
    # Drop the index
    op.drop_index('ix_sessions_last_activity_at', table_name='sessions')
    
    # Drop the column
    op.drop_column('sessions', 'last_activity_at') 