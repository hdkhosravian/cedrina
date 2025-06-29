from datetime import datetime  # For timestamp fields
from enum import Enum  # For type-safe role enumeration
from typing import Optional  # For optional fields

from pydantic import EmailStr, field_validator  # For email validation and custom validation
from sqlalchemy import DateTime, text  # For SQL expressions and explicit DateTime type
from sqlalchemy.dialects import postgresql  # Import PostgreSQL dialect
from sqlmodel import Column, Field, Index, SQLModel, String  # For ORM and table definition

from src.utils.i18n import get_translated_message  # For translation in validation


class Role(str, Enum):
    """Enumeration for user roles to support role-based access control (RBAC).

    Attributes:
        ADMIN: Represents an administrative user with elevated privileges.
        USER: Represents a standard user with basic access.

    """

    ADMIN = "admin"
    USER = "user"


class User(SQLModel, table=True):
    """User model for storing core user data, supporting both username/password and OAuth authentication.

    This model represents a user entity in the domain layer, encapsulating attributes for
    authentication, authorization, and auditing. It integrates with PostgreSQL via SQLModel
    and uses Pydantic for input validation.

    Attributes:
        id (Optional[int]): Primary key, auto-incremented by the database.
        username (str): Unique username for login, indexed for performance.
        email (EmailStr): Unique email address, validated by Pydantic.
        hashed_password (Optional[str]): Bcrypt-hashed password, null for OAuth-only users.
        role (Role): User role for RBAC, defaults to USER.
        is_active (bool): Account status, defaults to True (active).
        created_at (datetime): Timestamp of account creation, set by database.
        updated_at (Optional[datetime]): Timestamp of last update, updated by database.
        password_reset_token (Optional[str]): Secure token for password reset verification.
        password_reset_token_expires_at (Optional[datetime]): Expiration timestamp for password reset token.

    Table Arguments:
        Indexes on lower(username) and lower(email) for case-insensitive searches.
        Unique constraints on username and email to prevent duplicates.

    """

    __tablename__ = "users"  # Explicit table name for clarity

    id: Optional[int] = Field(
        default=None,  # Auto-incremented by database
        primary_key=True,  # Primary key constraint
        description="Unique identifier for the user",
    )
    username: str = Field(
        sa_column=Column(String, unique=True, index=True, nullable=False),  # Unique, indexed column
        min_length=3,  # Minimum length for security
        max_length=50,  # Maximum length for storage efficiency
        description="Unique username for login",
    )
    email: EmailStr = Field(
        sa_column=Column(String, unique=True, index=True, nullable=False),  # Unique, indexed column
        description="Unique email address validated by Pydantic",
    )
    hashed_password: Optional[str] = Field(
        max_length=255,  # Sufficient for bcrypt hashes
        description="Bcrypt-hashed password, null for OAuth-only users",
        default=None,  # Optional for OAuth users
    )
    role: Role = Field(
        sa_column=Column(
            postgresql.ENUM(Role, name="role", create_type=False),  # Use PostgreSQL enum
            default=Role.USER,  # Default to standard user
            nullable=False,
        ),
        description="User role for RBAC",
    )
    is_active: bool = Field(
        default=True,  # Active by default
        description="Account status (True for active, False for disabled)",
    )
    created_at: datetime = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            server_default=text("CURRENT_TIMESTAMP"),  # Database timestamp
            nullable=False,
        ),
        description="Account creation timestamp",
    )
    updated_at: Optional[datetime] = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            server_onupdate=text("CURRENT_TIMESTAMP"),  # Update on modification
            nullable=True,
        ),
        description="Last update timestamp",
    )
    password_reset_token: Optional[str] = Field(
        default=None,
        max_length=64,  # 32 bytes hex encoded = 64 characters
        description="Secure token for password reset verification",
    )
    password_reset_token_expires_at: Optional[datetime] = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            nullable=True,
        ),
        default=None,
        description="Expiration timestamp for password reset token",
    )

    __table_args__ = (
        Index("ix_users_username_lower", text("lower(username)")),  # Case-insensitive index
        Index("ix_users_email_lower", text("lower(email)")),  # Case-insensitive index
        {"extend_existing": True},
    )

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        """Ensures the username contains only allowed characters and normalizes to lowercase."""
        if not value.replace("_", "").replace("-", "").isalnum():
            raise ValueError(get_translated_message("invalid_username_characters", "en"))
        return value.lower()

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: EmailStr) -> EmailStr:
        """Normalizes email to lowercase for case-insensitive uniqueness."""
        return value.lower()
