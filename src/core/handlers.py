from __future__ import annotations

"""
Global exception handlers for the FastAPI application.

This module contains centralized handlers for custom application exceptions,
translating them into appropriate HTTP responses.
"""

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette import status
from structlog import get_logger
from slowapi.errors import RateLimitExceeded

from src.core.exceptions import (
    CedrinaError,
    AuthenticationError,
    DuplicateUserError,
    PasswordPolicyError,
    IncorrectPasswordError,
    PermissionError,
    DatabaseError,
)
from src.utils.i18n import get_translated_message, get_request_language

__all__ = [
    "authentication_error_handler",
    "duplicate_user_error_handler",
    "password_policy_error_handler",
    "incorrect_password_error_handler",
    "permission_error_handler",
    "rate_limit_exception_handler",
    "cedrina_error_handler",
]

logger = get_logger(__name__)


async def authentication_error_handler(request: Request, exc: AuthenticationError):
    """
    Handles AuthenticationError exceptions, returning a 401 Unauthorized response.
    """
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": str(exc)},
    )


async def duplicate_user_error_handler(request: Request, exc: DuplicateUserError) -> JSONResponse:
    """Handles DuplicateUserError exceptions, returning a 409 Conflict response."""
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={"detail": exc.message},
    )


async def password_policy_error_handler(request: Request, exc: PasswordPolicyError) -> JSONResponse:
    """Handles PasswordPolicyError exceptions, returning a 422 Unprocessable Entity response."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.message},
    )


async def incorrect_password_error_handler(request: Request, exc: IncorrectPasswordError) -> JSONResponse:
    """Return 400 Bad Request when the current password is incorrect."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": exc.message},
    )


async def permission_error_handler(request: Request, exc: PermissionError):
    """
    Handles PermissionError exceptions, returning a 403 Forbidden response.
    """
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": str(exc)},
    )


async def rate_limit_exception_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """
    Handles exceptions raised by slowapi when a rate limit is exceeded.

    This handler logs the event for security monitoring (SIEM) and returns a
    standardized 429 Too Many Requests response to the client. It includes the
    client's IP, the path they tried to access, and the specific rate limit
    that was triggered.

    Args:
        request: The incoming FastAPI request.
        exc: The RateLimitExceeded exception instance.

    Returns:
        A JSONResponse with status code 429.
    """
    locale = get_request_language(request)
    # The limit object has a 'limit' attribute which is a 'Limit' object.
    # The string representation of the 'Limit' object is the limit string (e.g. "10/minute").
    limit_scope = exc.limit.scope or "default"
    logger.warning(
        "rate_limit_exceeded",
        client_ip=request.client.host,
        path=request.url.path,
        limit=str(exc.limit),
        scope=limit_scope,
    )
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": get_translated_message("too_many_requests", locale)},
    )


async def cedrina_error_handler(request: Request, exc: CedrinaError) -> JSONResponse:
    """
    Handles CedrinaError exceptions, returning a 500 Internal Server Error response.
    """
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": str(exc)},
    ) 