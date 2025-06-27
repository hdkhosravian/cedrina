from __future__ import annotations

"""Factory for generating fake user data for testing."""

from datetime import datetime, timezone
from typing import Optional, List

from faker import Faker
from pydantic import EmailStr

from src.domain.entities.user import User, Role

fake = Faker()


def create_fake_user(
    id: Optional[int] = None,
    username: Optional[str] = None,
    email: Optional[EmailStr] = None,
    hashed_password: Optional[str] = None,
    role: Optional[Role] = Role.USER,
    is_active: bool = True,
    created_at: Optional[datetime] = None,
    updated_at: Optional[datetime] = None,
    roles: Optional[List[Role]] = None
) -> User:
    """Create a fake User entity for testing.

    Args:
        id (Optional[int]): User ID, defaults to a random integer.
        username (Optional[str]): Username, defaults to a fake username.
        email (Optional[EmailStr]): Email, defaults to a fake email.
        hashed_password (Optional[str]): Hashed password, defaults to a fake password.
        role (Optional[Role]): User role, defaults to USER.
        is_active (bool): Whether the user is active, defaults to True.
        created_at (Optional[datetime]): Creation timestamp, defaults to now.
        updated_at (Optional[datetime]): Update timestamp, defaults to None.
        roles (Optional[List[Role]]): List of roles, defaults to None.

    Returns:
        User: A fake User entity.
    """
    return User(
        id=id if id is not None else fake.random_int(min=1, max=10000),
        username=username if username is not None else fake.user_name(),
        email=email if email is not None else fake.email(),
        hashed_password=hashed_password if hashed_password is not None else fake.password(length=12, special_chars=True, digits=True, upper_case=True, lower_case=True),
        role=role,
        is_active=is_active,
        created_at=created_at if created_at is not None else datetime.now(timezone.utc),
        updated_at=updated_at,
        roles=roles if roles is not None else [role]
    ) 