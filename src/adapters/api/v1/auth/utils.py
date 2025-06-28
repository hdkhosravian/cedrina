from __future__ import annotations

"""Utility functions for authentication API routes.

This module provides shared helper functions to ensure consistency and reduce
duplication across authentication endpoints like login, register, and OAuth.
"""

from src.adapters.api.v1.auth.schemas import TokenPair
from src.core.config.settings import settings
from src.domain.entities.user import User
from src.domain.services.auth.token import TokenService


async def create_token_pair(token_service: TokenService, user: User) -> TokenPair:
    """Create a pair of JWT access and refresh tokens for a user.

    This utility centralizes token creation logic to ensure consistency across
    authentication endpoints. It generates access and refresh tokens using the
    provided token service and applies configuration from settings.

    Args:
        token_service (TokenService): Service for token generation.
        user (User): The user entity for whom tokens are created.

    Returns:
        TokenPair: Pydantic model with access token, refresh token, token type,
            and expiration time in seconds.

    Note:
        - Expiration time (`expires_in`) is derived from settings and validated
          to prevent invalid values (e.g., negative or zero).
        - Tokens are created asynchronously to align with FastAPI's async nature.

    """
    access_token = await token_service.create_access_token(user=user)
    refresh_token = await token_service.create_refresh_token(user=user)

    # Validate expires_in to prevent invalid values.
    expires_in = max(settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60, 60)  # At least 60s.

    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="Bearer",
        expires_in=expires_in,
    )
