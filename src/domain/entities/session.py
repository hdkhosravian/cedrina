from datetime import datetime  # For timestamp fields
from typing import Optional  # For optional fields
from uuid import uuid4  # For generating unique JWT IDs

from sqlalchemy import DateTime, text  # For SQL expressions and explicit DateTime type
from sqlalchemy.dialects.postgresql import UUID  # For UUID-based JWT ID
from sqlmodel import Column, Field, Index, SQLModel  # For ORM and table definition


class Session(SQLModel, table=True):
    """Represents a user's session, acting as an entity within the Authentication Bounded Context.

    This entity tracks an authenticated user's session, identified by a unique
    JWT ID (jti). It is fundamental for managing session lifecycle, including
    token rotation, revocation, and tracking user activity.

    Each session is uniquely tied to a user and contains the necessary data to
    validate refresh tokens securely.

    Attributes:
        id: The unique identifier for the session record.
        jti: The unique JWT ID (claim 'jti'), used as the primary means of
            revoking a specific token chain.
        user_id: A foreign key linking the session to the `User` aggregate root.
        refresh_token_hash: The securely hashed refresh token, preventing direct
            token exposure in the database.
        created_at: The timestamp when the session was initiated.
        expires_at: The timestamp when the refresh token is no longer valid.
        last_activity_at: The timestamp of the last authenticated action, used
            to detect and expire inactive sessions.
        revoked_at: The timestamp when the session was explicitly revoked. A null
            value indicates the session is still active.
    """

    __tablename__ = "sessions"  # Explicit table name for clarity

    id: Optional[int] = Field(
        default=None,  # Auto-incremented by database
        primary_key=True,  # Primary key constraint
        description="The unique identifier for the session record.",
    )
    jti: str = Field(
        default_factory=lambda: str(uuid4()),  # Generate UUID for JWT ID
        sa_column=Column(
            UUID(as_uuid=False), unique=True, index=True, nullable=False
        ),  # UUID column
        description="Unique JWT ID (jti) for token revocation.",
    )
    user_id: int = Field(
        foreign_key="users.id",  # References users table
        index=True,  # Index for performance
        nullable=False,  # Required field
        description="Foreign key linking the session to the User.",
    )
    refresh_token_hash: str = Field(
        max_length=255,  # Sufficient for hashed tokens
        description="Hashed refresh token for secure validation.",
        nullable=False,  # Required for security
    )
    created_at: datetime = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            server_default=text("CURRENT_TIMESTAMP"),  # Database timestamp
            nullable=False,
        ),
        description="The timestamp when the session was initiated.",
    )
    expires_at: datetime = Field(
        sa_column=Column(DateTime, nullable=False),  # Explicit DateTime type for Alembic
        description="The timestamp when the refresh token expires.",
    )
    last_activity_at: datetime = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            server_default=text("CURRENT_TIMESTAMP"),  # Database timestamp
            nullable=False,
        ),
        description="Timestamp of the last user activity, for inactivity tracking.",
    )
    revoked_at: Optional[datetime] = Field(
        sa_column=Column(DateTime, nullable=True),  # Explicit DateTime type for Alembic
        description="Timestamp of when the session was revoked. Null if active.",
    )

    __table_args__ = (
        Index("ix_sessions_jti", "jti"),  # Index for revocation checks
        Index(
            "ix_sessions_user_id_expires_at", "user_id", "expires_at"
        ),  # Index for session queries
        Index(
            "ix_sessions_last_activity_at", "last_activity_at"
        ),  # Index for inactivity-based cleanup
        {"extend_existing": True},
    )
