from __future__ import annotations

"""FastAPI dependency providers for authentication services."""

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Annotated

from src.domain.services.auth.user_authentication import UserAuthenticationService
from src.domain.services.auth.token import TokenService
from src.domain.services.auth.oauth import OAuthService
from src.infrastructure.redis import get_redis
from src.infrastructure.database.async_db import get_async_db

# ---------------------------------------------------------------------------
# Type aliases for dependency overrides – keeps signature noise low.
# ---------------------------------------------------------------------------

AsyncDB = Annotated[AsyncSession, Depends(get_async_db)]
RedisClient = Annotated[Redis, Depends(get_redis)]

# ---------------------------------------------------------------------------
# Public factories
# ---------------------------------------------------------------------------


def get_user_auth_service(db: AsyncDB) -> UserAuthenticationService:  # noqa: D401
    """Factory that returns :class:`UserAuthenticationService`."""

    return UserAuthenticationService(db)


def get_token_service(db: AsyncDB, redis: RedisClient) -> TokenService:  # noqa: D401
    """Factory that returns :class:`TokenService`."""

    return TokenService(db, redis)


def get_oauth_service(db: AsyncDB) -> OAuthService:  # noqa: D401
    """Factory that returns :class:`OAuthService`.  No Redis needed here."""

    return OAuthService(db) 