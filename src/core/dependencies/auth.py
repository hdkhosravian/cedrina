from __future__ import annotations

# FastAPI & typing
from typing import Annotated

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

# Project imports
from src.domain.entities.user import User, Role
from src.domain.services.auth.token import TokenService
from src.infrastructure.database import get_db
from src.infrastructure.redis import get_redis
from src.core.exceptions import PermissionError, AuthenticationError
from src.utils.i18n import get_translated_message

__all__ = [
    "get_current_user",
    "get_current_admin_user",
]


# ---------------------------------------------------------------------------
# Type-annotated dependency shortcuts
# ---------------------------------------------------------------------------


TokenStr = Annotated[str, Depends(OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token"))]
DBSession = Annotated[AsyncSession, Depends(get_db)]
RedisClient = Annotated[Redis, Depends(get_redis)]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _auth_fail(request: Request, key: str) -> HTTPException:  # noqa: D401
    """Consistently shaped *401* UNAUTHORIZED response."""
    detail = get_translated_message(key, request.state.language)
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


# ---------------------------------------------------------------------------
# Public dependencies
# ---------------------------------------------------------------------------


async def get_current_user(  # noqa: D401
    request: Request, token: TokenStr, db_session: DBSession, redis_client: RedisClient
) -> User:
    """Return the authenticated :class:`~src.domain.entities.user.User`.

    The function performs **no** role checks; it merely authenticates the JWT and
    looks up the corresponding user-record.  Call :pyfunc:`get_current_admin_user`
    for role-enforced logic.
    """

    try:
        payload = await TokenService(db_session, redis_client).validate_token(token)
        user_id = payload.get("sub")
        if user_id is None:
            raise _auth_fail(request, "invalid_token_subject")

        user = await db_session.get(User, int(user_id))
        if user is None or not user.is_active:
            raise _auth_fail(request, "user_not_found_or_inactive")
        return user
    except AuthenticationError as exc:
        # Here we translate the exception message itself, assuming it's a valid key
        raise _auth_fail(request, str(exc)) from exc


def get_current_admin_user(
    request: Request, current_user: Annotated[User, Depends(get_current_user)]
) -> User:  # noqa: D401
    """Ensure the authenticated user has *ADMIN* role."""

    if current_user.role != Role.ADMIN:
        message = get_translated_message("admin_privileges_required", request.state.language)
        raise PermissionError(message)
    return current_user 