from __future__ import annotations

"""Factory for generating fake OAuth data for testing."""

from datetime import datetime, timedelta
from typing import Any, Dict, Literal

from faker import Faker

fake = Faker()


def create_fake_oauth_token(
    provider: Literal["google", "microsoft", "facebook"] = "google",
    access_token: str = None,
    expires_at: int = None,
) -> Dict[str, Any]:
    """Create a fake OAuth token dictionary for testing.

    Args:
        provider (Literal["google", "microsoft", "facebook"], optional): OAuth provider, defaults to 'google'.
        access_token (str, optional): Access token, defaults to a fake token.
        expires_at (int, optional): Expiration timestamp, defaults to a future timestamp.

    Returns:
        Dict[str, Any]: A dictionary representing an OAuth token.

    """
    return {
        "access_token": access_token if access_token else fake.sha256(),
        "expires_at": (
            expires_at
            if expires_at is not None
            else int((datetime.now() + timedelta(days=1)).timestamp())
        ),
    }


def create_fake_oauth_user_info(
    provider: Literal["google", "microsoft", "facebook"] = "google",
    email: str = None,
    sub: str = None,
    id: str = None,
) -> Dict[str, Any]:
    """Create fake OAuth user info for testing.

    Args:
        provider (Literal["google", "microsoft", "facebook"], optional): OAuth provider, defaults to 'google'.
        email (str, optional): User email, defaults to a fake email.
        sub (str, optional): Subject ID, defaults to a fake ID (used by Google/Microsoft).
        id (str, optional): User ID, defaults to a fake ID (used by Facebook).

    Returns:
        Dict[str, Any]: A dictionary representing OAuth user info.

    """
    return {
        "email": email if email else fake.email(),
        "sub": sub if sub else fake.uuid4() if provider != "facebook" else None,
        "id": id if id else fake.uuid4() if provider == "facebook" else None,
        "name": fake.name(),
    }
