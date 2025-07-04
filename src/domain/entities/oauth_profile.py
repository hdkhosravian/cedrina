from datetime import datetime  # For timestamp fields
from enum import Enum  # For type-safe provider enumeration
from typing import Optional  # For optional fields

from sqlalchemy import DateTime, LargeBinary, String, text  # Import String and SQL expressions
from sqlalchemy.dialects import postgresql  # Import PostgreSQL dialect
from sqlmodel import Column, Field, Index, SQLModel  # For ORM and table definition


class Provider(str, Enum):
    """A Value Object representing the supported OAuth providers.

    This enumeration ensures that only recognized and configured OAuth providers
    can be associated with a user's profile, providing type safety and
    domain consistency.

    Attributes:
        GOOGLE: Represents the Google OAuth 2.0 provider.
        MICROSOFT: Represents the Microsoft Identity Platform (OAuth 2.0) provider.
        FACEBOOK: Represents the Facebook Login (OAuth 2.0) provider.
    """

    GOOGLE = "google"
    MICROSOFT = "microsoft"
    FACEBOOK = "facebook"


class OAuthProfile(SQLModel, table=True):
    """Represents a link between a User and an external OAuth provider.

    This entity, part of the Authentication Bounded Context, stores the necessary
    information to manage a user's identity as provided by a third-party OAuth
    service. It ensures that a user's account can be securely associated with
    one or more external login methods.

    The access token is encrypted at rest in the database for security.

    Attributes:
        id: The unique identifier for the OAuth profile record.
        user_id: A foreign key that links this profile to the main `User` aggregate.
        provider: The specific OAuth provider this profile is for (e.g., Google).
        provider_user_id: The unique identifier for the user as provided by the
            external OAuth service.
        access_token: The encrypted OAuth access token, required for making API
            calls on behalf of the user.
        expires_at: The timestamp when the access token is no longer valid.
        created_at: The timestamp when this OAuth profile was first created.
        updated_at: The timestamp of the last update to this profile, such as a
            token refresh.
    """

    __tablename__ = "oauth_profiles"  # Explicit table name for clarity

    id: Optional[int] = Field(
        default=None,  # Auto-incremented by database
        primary_key=True,  # Primary key constraint
        description="The unique identifier for the OAuth profile.",
    )
    user_id: int = Field(
        foreign_key="users.id",  # References users table
        nullable=False,  # Required field
        description="Foreign key linking this profile to a User.",
    )
    provider: Provider = Field(
        sa_column=Column(
            postgresql.ENUM(Provider, name="provider", create_type=False),  # Use PostgreSQL enum
            nullable=False,
        ),
        description="The OAuth provider (e.g., Google, Microsoft, Facebook).",
    )
    provider_user_id: str = Field(
        sa_column=Column(String, nullable=False),  # Provider's user ID
        description="The unique identifier for the user from the OAuth provider.",
    )
    access_token: bytes = Field(
        sa_column=Column(LargeBinary, nullable=False),  # Encrypted token
        description="The encrypted OAuth access token.",
    )
    expires_at: datetime = Field(
        nullable=False,  # Required for token validity
        description="The expiration timestamp for the access token.",
    )
    created_at: datetime = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            server_default=text("CURRENT_TIMESTAMP"),  # Database timestamp
            nullable=False,
        ),
        description="The timestamp when the OAuth profile was created.",
    )
    updated_at: Optional[datetime] = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            server_onupdate=text("CURRENT_TIMESTAMP"),  # Update on modification
            nullable=True,
        ),
        description="The timestamp of the last profile update (e.g., token refresh).",
    )

    __table_args__ = (
        Index(
            "ix_oauth_profiles_provider_user_id", "provider", "provider_user_id", unique=True
        ),  # Unique constraint
        Index("ix_oauth_profiles_user_id", "user_id"),  # Index for joins
        {"extend_existing": True},
    )
