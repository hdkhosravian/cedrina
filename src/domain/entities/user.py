from datetime import datetime  # For timestamp fields
from enum import Enum  # For type-safe role enumeration
from typing import Optional  # For optional fields

from pydantic import EmailStr, field_validator  # For email validation and custom validation
from sqlalchemy import DateTime, text  # For SQL expressions and explicit DateTime type
from sqlalchemy.dialects import postgresql  # Import PostgreSQL dialect
from sqlmodel import Column, Field, Index, SQLModel, String  # For ORM and table definition

from src.utils.i18n import get_translated_message  # For translation in validation
from src.core.config.settings import settings


class Role(str, Enum):
    """Represents the role of a user within the system (RBAC).

    This value object defines the possible roles a user can have, ensuring that
    role assignments are type-safe and constrained to a predefined set.

    Attributes:
        ADMIN: Confers administrative privileges for system management.
        USER: Represents a standard user with regular access rights.
    """

    ADMIN = "admin"
    USER = "user"


class User(SQLModel, table=True):
    """Represents a User entity and acts as an Aggregate Root.

    This class models a user within the domain, encapsulating all properties
    and business rules related to a user's identity, authentication, and
    authorization. As an aggregate root, it is the primary object through which
    all user-related operations should be performed.

    The model supports both traditional password-based authentication and
    external OAuth providers.

    Attributes:
        id: The unique identifier for the user (primary key).
        username: A unique, case-insensitive username for login.
        email: A unique, case-insensitive email address.
        hashed_password: The securely hashed password (using bcrypt). Null for
            users who only authenticate via OAuth.
        role: The user's role, determining their permissions within the system.
        is_active: A flag indicating if the user's account is active. Inactive
            users cannot log in.
        created_at: The timestamp of when the user account was created.
        updated_at: The timestamp of the last update to the user's record.
        password_reset_token: A secure token for verifying a password reset request.
        password_reset_token_expires_at: The expiration timestamp for the reset token.
    """

    __tablename__ = "users"  # Explicit table name for clarity

    id: Optional[int] = Field(
        default=None,  # Auto-incremented by database
        primary_key=True,  # Primary key constraint
        description="The unique identifier for the user.",
    )
    username: str = Field(
        sa_column=Column(String, unique=True, index=True, nullable=False),  # Unique, indexed column
        min_length=3,  # Minimum length for security
        max_length=50,  # Maximum length for storage efficiency
        description="Unique, case-insensitive username for login.",
    )
    email: EmailStr = Field(
        sa_column=Column(String, unique=True, index=True, nullable=False),  # Unique, indexed column
        description="Unique, case-insensitive email address for communication and login.",
    )
    hashed_password: Optional[str] = Field(
        max_length=255,  # Sufficient for bcrypt hashes
        description="Bcrypt-hashed password. Null for users authenticating via OAuth.",
        default=None,  # Optional for OAuth users
    )
    role: Role = Field(
        sa_column=Column(
            postgresql.ENUM(Role, name="role", create_type=False),  # Use PostgreSQL enum
            default=Role.USER,  # Default to standard user
            nullable=False,
        ),
        description="The user's role, used for role-based access control (RBAC).",
    )
    is_active: bool = Field(
        default=True,  # Active by default
        description="Indicates if the user's account is active. Inactive users cannot log in.",
    )
    email_confirmed: bool = Field(
        default_factory=lambda: not settings.EMAIL_CONFIRMATION_ENABLED,
        description="Indicates if the user's email has been confirmed.",
    )
    created_at: datetime = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            server_default=text("CURRENT_TIMESTAMP"),  # Database timestamp
            nullable=False,
        ),
        description="The timestamp of when the user account was created.",
    )
    updated_at: Optional[datetime] = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            server_onupdate=text("CURRENT_TIMESTAMP"),  # Update on modification
            nullable=True,
        ),
        description="The timestamp of the last update to the user's record.",
    )
    password_reset_token: Optional[str] = Field(
        default=None,
        max_length=64,  # 32 bytes hex encoded = 64 characters
        description="A secure token for verifying a password reset request.",
    )
    password_reset_token_expires_at: Optional[datetime] = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            nullable=True,
        ),
        default=None,
        description="The expiration timestamp for the password reset token.",
    )
    email_confirmation_token: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Token used for confirming user email address.",
    )

    __table_args__ = (
        Index("ix_users_username_lower", text("lower(username)")),  # Case-insensitive index
        Index("ix_users_email_lower", text("lower(email)")),  # Case-insensitive index
        {"extend_existing": True},
    )

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        """Validates and normalizes the username.

        Ensures the username contains only alphanumeric characters, underscores,
        or hyphens, and converts it to lowercase to enforce case-insensitivity.

        Raises:
            ValueError: If the username contains invalid characters.
        """
        if not value.replace("_", "").replace("-", "").isalnum():
            raise ValueError(
                get_translated_message("invalid_username_characters", "en")
            )
        return value.lower()

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: EmailStr) -> str:
        """Normalizes the email address to lowercase.

        This ensures that email addresses are stored and compared in a
        case-insensitive manner, preventing duplicate accounts with different
        casing.
        """
        return value.lower()
