from __future__ import annotations

"""
Global exception handlers for the FastAPI application.

This module contains centralized handlers for custom application exceptions,
translating them into appropriate HTTP responses.
"""

from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from starlette import status
from structlog import get_logger

from src.core.exceptions import (
    AuthenticationError,
    CedrinaError,
    DatabaseError,
    DuplicateUserError,
    EmailServiceError,
    ForgotPasswordError,
    InvalidOldPasswordError,
    PasswordPolicyError,
    PasswordResetError,
    PasswordReuseError,
    PasswordValidationError,
    PermissionError,
    RateLimitExceededError,
    UserNotFoundError,
)
from src.utils.i18n import get_request_language, get_translated_message

__all__ = [
    "authentication_error_handler",
    "duplicate_user_error_handler",
    "password_policy_error_handler",
    "permission_error_handler",
    "rate_limit_exception_handler",
    "rate_limit_exceeded_error_handler",
    "forgot_password_error_handler",
    "password_reset_error_handler",
    "email_service_error_handler",
    "user_not_found_error_handler",
    "cedrina_error_handler",
    "password_validation_error_handler",
    "invalid_old_password_error_handler",
    "password_reuse_error_handler",
    "database_error_handler",
    "register_exception_handlers",
]

logger = get_logger(__name__)


async def authentication_error_handler(request: Request, exc: AuthenticationError):
    """Handles AuthenticationError exceptions, returning a 401 Unauthorized response."""
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


async def password_validation_error_handler(
    request: Request, exc: PasswordValidationError
) -> JSONResponse:
    """Handles PasswordValidationError exceptions, returning a 400 Bad Request response."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": exc.message},
    )


async def invalid_old_password_error_handler(
    request: Request, exc: InvalidOldPasswordError
) -> JSONResponse:
    """Handles InvalidOldPasswordError exceptions, returning a 400 Bad Request response."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": exc.message},
    )


async def password_reuse_error_handler(request: Request, exc: PasswordReuseError) -> JSONResponse:
    """Handles PasswordReuseError exceptions, returning a 400 Bad Request response."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": exc.message},
    )


async def permission_error_handler(request: Request, exc: PermissionError):
    """Handles PermissionError exceptions, returning a 403 Forbidden response."""
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": str(exc)},
    )


async def rate_limit_exception_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Handles exceptions raised by slowapi when a rate limit is exceeded.

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


async def rate_limit_exceeded_error_handler(request: Request, exc: RateLimitExceededError) -> JSONResponse:
    """Handles RateLimitExceededError exceptions from domain services, returning a 429 Too Many Requests response."""
    locale = get_request_language(request)
    logger.warning(
        "domain_rate_limit_exceeded",
        client_ip=request.client.host,
        path=request.url.path,
        error_message=str(exc),
    )
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": exc.message},
    )


async def forgot_password_error_handler(request: Request, exc: ForgotPasswordError) -> JSONResponse:
    """Handles ForgotPasswordError exceptions, returning a 400 Bad Request response."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": exc.message},
    )


async def password_reset_error_handler(request: Request, exc: PasswordResetError) -> JSONResponse:
    """Handles PasswordResetError exceptions, returning a 400 Bad Request response."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": exc.message},
    )


async def email_service_error_handler(request: Request, exc: EmailServiceError) -> JSONResponse:
    """Handles EmailServiceError exceptions, returning a 500 Internal Server Error response."""
    logger.error(
        "email_service_error",
        error_message=str(exc),
        client_ip=request.client.host,
        path=request.url.path,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": exc.message},
    )


async def user_not_found_error_handler(request: Request, exc: UserNotFoundError) -> JSONResponse:
    """Handles UserNotFoundError exceptions, returning a 404 Not Found response."""
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": exc.message},
    )


async def cedrina_error_handler(request: Request, exc: CedrinaError) -> JSONResponse:
    """Handles CedrinaError exceptions, returning a 500 Internal Server Error response."""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": str(exc)},
    )


async def database_error_handler(request: Request, exc: DatabaseError) -> JSONResponse:
    """Handles DatabaseError exceptions, returning a 500 Internal Server Error response."""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": exc.message}
    )


def register_exception_handlers(app) -> None:
    """Register all exception handlers with the FastAPI application.
    
    Args:
        app: The FastAPI application instance
    """
    from slowapi.errors import RateLimitExceeded
    
    app.add_exception_handler(RateLimitExceeded, rate_limit_exception_handler)
    app.add_exception_handler(RateLimitExceededError, rate_limit_exceeded_error_handler)
    app.add_exception_handler(AuthenticationError, authentication_error_handler)
    app.add_exception_handler(PermissionError, permission_error_handler)
    app.add_exception_handler(DuplicateUserError, duplicate_user_error_handler)
    app.add_exception_handler(ForgotPasswordError, forgot_password_error_handler)
    app.add_exception_handler(PasswordResetError, password_reset_error_handler)
    app.add_exception_handler(PasswordPolicyError, password_policy_error_handler)
    app.add_exception_handler(PasswordValidationError, password_validation_error_handler)
    app.add_exception_handler(InvalidOldPasswordError, invalid_old_password_error_handler)
    app.add_exception_handler(PasswordReuseError, password_reuse_error_handler)
    app.add_exception_handler(EmailServiceError, email_service_error_handler)
    app.add_exception_handler(UserNotFoundError, user_not_found_error_handler)
    app.add_exception_handler(DatabaseError, database_error_handler)
