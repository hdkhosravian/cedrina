from datetime import datetime  # For timestamp fields
from typing import Optional  # For optional fields
from uuid import uuid4  # For generating unique JWT IDs
from sqlmodel import SQLModel, Field, Column, Index  # For ORM and table definition
from sqlalchemy.dialects.postgresql import UUID  # For UUID-based JWT ID
from sqlalchemy import text, DateTime  # For SQL expressions and explicit DateTime type

class Session(SQLModel, table=True):
    """
    Session model for tracking JWT refresh tokens and session state.
    
    This model stores session data for user authentication, including refresh token
    hashes and JWT IDs (jti) for revocation. It supports token rotation and session
    management, integrating with PostgreSQL for persistence and Redis for caching.
    
    Attributes:
        id (Optional[int]): Primary key, auto-incremented by the database.
        jti (str): Unique JWT ID (UUID) for token revocation.
        user_id (int): Foreign key referencing the User model.
        refresh_token_hash (str): Hashed refresh token for validation.
        created_at (datetime): Session creation timestamp.
        expires_at (datetime): Refresh token expiration timestamp.
        revoked_at (Optional[datetime]): Revocation timestamp, null if active.
    
    Table Arguments:
        Unique index on jti for fast revocation checks.
        Index on user_id and expires_at for efficient session queries.
    """
    __tablename__ = "sessions"  # Explicit table name for clarity

    id: Optional[int] = Field(
        default=None,  # Auto-incremented by database
        primary_key=True,  # Primary key constraint
        description="Unique identifier for the session"
    )
    jti: str = Field(
        default_factory=lambda: str(uuid4()),  # Generate UUID for JWT ID
        sa_column=Column(UUID(as_uuid=False), unique=True, index=True, nullable=False),  # UUID column
        description="Unique JWT ID for token revocation"
    )
    user_id: int = Field(
        foreign_key="users.id",  # References users table
        index=True,  # Index for performance
        nullable=False,  # Required field
        description="Foreign key referencing the User"
    )
    refresh_token_hash: str = Field(
        max_length=255,  # Sufficient for hashed tokens
        description="Hashed refresh token for validation",
        nullable=False  # Required for security
    )
    created_at: datetime = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            server_default=text("CURRENT_TIMESTAMP"),  # Database timestamp
            nullable=False
        ),
        description="Session creation timestamp"
    )
    expires_at: datetime = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            nullable=False
        ),
        description="Refresh token expiration timestamp"
    )
    revoked_at: Optional[datetime] = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            nullable=True
        ),
        description="Revocation timestamp, null if session is active"
    )

    __table_args__ = (
        Index("ix_sessions_jti", "jti"),  # Index for revocation checks
        Index("ix_sessions_user_id_expires_at", "user_id", "expires_at"),  # Index for session queries
        {"extend_existing": True},
    )
