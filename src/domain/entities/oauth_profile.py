from datetime import datetime  # For timestamp fields
from enum import Enum  # For type-safe provider enumeration
from typing import Optional  # For optional fields

from sqlalchemy import DateTime, LargeBinary, String, text  # Import String and SQL expressions
from sqlalchemy.dialects import postgresql  # Import PostgreSQL dialect
from sqlmodel import Column, Field, Index, SQLModel  # For ORM and table definition


class Provider(str, Enum):
    """Enumeration for OAuth providers supported by the authentication system.

    Attributes:
        GOOGLE: Google OAuth provider.
        MICROSOFT: Microsoft OAuth provider.
        FACEBOOK: Facebook OAuth provider.

    """

    GOOGLE = "google"
    MICROSOFT = "microsoft"
    FACEBOOK = "facebook"


class OAuthProfile(SQLModel, table=True):
    """OAuthProfile model for linking users to OAuth provider accounts.

    This model stores provider-specific user data, including encrypted access tokens
    using PostgreSQL's pgcrypto extension. It associates OAuth accounts with users
    via a foreign key and ensures uniqueness per provider and user ID.

    Attributes:
        id (Optional[int]): Primary key, auto-incremented by the database.
        user_id (int): Foreign key referencing the User model.
        provider (Provider): OAuth provider (e.g., google, microsoft, facebook).
        provider_user_id (str): Unique user ID from the provider.
        access_token (bytes): Encrypted OAuth access token (pgcrypto).
        expires_at (datetime): Access token expiration timestamp.
        created_at (datetime): Profile creation timestamp.
        updated_at (Optional[datetime]): Last update timestamp.

    Table Arguments:
        Unique index on provider and provider_user_id to prevent duplicate profiles.
        Index on user_id for efficient queries.

    """

    __tablename__ = "oauth_profiles"  # Explicit table name for clarity

    id: Optional[int] = Field(
        default=None,  # Auto-incremented by database
        primary_key=True,  # Primary key constraint
        description="Unique identifier for the OAuth profile",
    )
    user_id: int = Field(
        foreign_key="users.id",  # References users table
        nullable=False,  # Required field
        description="Foreign key referencing the User",
    )
    provider: Provider = Field(
        sa_column=Column(
            postgresql.ENUM(Provider, name="provider", create_type=False),  # Use PostgreSQL enum
            nullable=False,
        ),
        description="OAuth provider (google, microsoft, facebook)",
    )
    provider_user_id: str = Field(
        sa_column=Column(String, nullable=False),  # Provider's user ID
        description="Unique user ID from the OAuth provider",
    )
    access_token: bytes = Field(
        sa_column=Column(LargeBinary, nullable=False),  # Encrypted token
        description="Encrypted OAuth access token using pgcrypto",
    )
    expires_at: datetime = Field(
        nullable=False,  # Required for token validity
        description="Access token expiration timestamp",
    )
    created_at: datetime = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            server_default=text("CURRENT_TIMESTAMP"),  # Database timestamp
            nullable=False,
        ),
        description="Profile creation timestamp",
    )
    updated_at: Optional[datetime] = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            server_onupdate=text("CURRENT_TIMESTAMP"),  # Update on modification
            nullable=True,
        ),
        description="Last update timestamp",
    )

    __table_args__ = (
        Index(
            "ix_oauth_profiles_provider_user_id", "provider", "provider_user_id", unique=True
        ),  # Unique constraint
        Index("ix_oauth_profiles_user_id", "user_id"),  # Index for joins
        {"extend_existing": True},
    )
