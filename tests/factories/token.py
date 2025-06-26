from __future__ import annotations

"""Factory for generating fake token data for testing."""

from typing import Dict, Any

from faker import Faker

fake = Faker()


def create_fake_token(
    access_token: str = None,
    refresh_token: str = None,
    token_type: str = "Bearer"
) -> Dict[str, Any]:
    """Create a fake token dictionary for testing.

    Args:
        access_token (str, optional): Access token, defaults to a fake JWT-like string.
        refresh_token (str, optional): Refresh token, defaults to a fake JWT-like string.
        token_type (str, optional): Token type, defaults to 'Bearer'.

    Returns:
        Dict[str, Any]: A dictionary representing a token pair.
    """
    return {
        "access_token": access_token if access_token else f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{fake.sha256()}.{fake.sha256()}",
        "refresh_token": refresh_token if refresh_token else f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{fake.sha256()}.{fake.sha256()}",
        "token_type": token_type
    } 