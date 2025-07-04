from __future__ import annotations

"""
Global exception handlers for the FastAPI application.

This module contains centralized handlers for custom application exceptions,
translating them into appropriate HTTP responses.
"""

from fastapi import Request, FastAPI
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


async def authentication_error_handler(request: Request, exc: AuthenticationError) -> JSONResponse:
    """Handles `AuthenticationError`, returning a `401 Unauthorized`.

    This handler catches exceptions related to failed authentication, such as
    invalid credentials, expired tokens, or inactive users.

    Args:
        request: The incoming `Request` object.
        exc: The `AuthenticationError` instance.

    Returns:
        A `JSONResponse` with a 401 status code and error detail.
    """
    logger.warning(
        "Authentication failure",
        error=exc.code,
        client_ip=request.client.host,
        path=request.url.path,
    )
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": str(exc)},
    )


async def duplicate_user_error_handler(request: Request, exc: DuplicateUserError) -> JSONResponse:
    """Handles `DuplicateUserError`, returning a `409 Conflict`.

    This is triggered when a registration attempt is made with a username or
    email that already exists in the system.

    Args:
        request: The incoming `Request` object.
        exc: The `DuplicateUserError` instance.

    Returns:
        A `JSONResponse` with a 409 status code and error detail.
    """
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={"detail": exc.message},
    )


async def password_policy_error_handler(request: Request, exc: PasswordPolicyError) -> JSONResponse:
    """Handles `PasswordPolicyError`, returning a `422 Unprocessable Entity`.

    This error occurs when a new password does not meet the application's
    security requirements (e.g., length, complexity).

    Args:
        request: The incoming `Request` object.
        exc: The `PasswordPolicyError` instance.

    Returns:
        A `JSONResponse` with a 422 status code and error detail.
    """
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.message},
    )


async def password_validation_error_handler(
    request: Request, exc: PasswordValidationError
) -> JSONResponse:
    """Handles `PasswordValidationError`, returning a `400 Bad Request`.

    This handler catches validation errors during password change operations,
    such as when the new password is the same as the old one.

    Args:
        request: The incoming `Request` object.
        exc: The `PasswordValidationError` instance.

    Returns:
        A `JSONResponse` with a 400 status code and error detail.
    """
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": exc.message},
    )


async def invalid_old_password_error_handler(
    request: Request, exc: InvalidOldPasswordError
) -> JSONResponse:
    """Handles `InvalidOldPasswordError`, returning a `400 Bad Request`.

    This is triggered during a password change if the provided "old" password
    does not match the user's current password.

    Args:
        request: The incoming `Request` object.
        exc: The `InvalidOldPasswordError` instance.

    Returns:
        A `JSONResponse` with a 400 status code and error detail.
    """
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": exc.message},
    )


async def password_reuse_error_handler(request: Request, exc: PasswordReuseError) -> JSONResponse:
    """Handles `PasswordReuseError`, returning a `400 Bad Request`.

    This occurs when a user tries to change their password to one they have
    used recently, violating the password history policy.

    Args:
        request: The incoming `Request` object.
        exc: The `PasswordReuseError` instance.

    Returns:
        A `JSONResponse` with a 400 status code and error detail.
    """
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": exc.message},
    )


async def permission_error_handler(request: Request, exc: PermissionError) -> JSONResponse:
    """Handles `PermissionError`, returning a `403 Forbidden`.

    This handler is invoked when an authenticated user attempts to perform an
    action for which they do not have sufficient privileges.

    Args:
        request: The incoming `Request` object.
        exc: The `PermissionError` instance.

    Returns:
        A `JSONResponse` with a 403 status code and error detail.
    """
    logger.warning(
        "Permission denied",
        error=exc.code,
        client_ip=request.client.host,
        path=request.url.path,
    )
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
    """Handles domain-specific `RateLimitExceededError`, returning a `429`.

    This catches rate limit exceptions originating from within the domain logic,
    as opposed to the middleware-level handler.

    Args:
        request: The incoming `Request` object.
        exc: The `RateLimitExceededError` instance.

    Returns:
        A `JSONResponse` with a 429 status code and error detail.
    """
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
    """Handles `ForgotPasswordError`, returning a `400 Bad Request`.

    This catches errors during the initiation of a password reset, such as
    an invalid email format or other validation failures.

    Args:
        request: The incoming `Request` object.
        exc: The `ForgotPasswordError` instance.

    Returns:
        A `JSONResponse` with a 400 status code and error detail.
    """
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": exc.message},
    )


async def password_reset_error_handler(request: Request, exc: PasswordResetError) -> JSONResponse:
    """Handles `PasswordResetError`, returning a `400 Bad Request`.

    This is for errors during the final step of a password reset, such as
    using an invalid or expired token.

    Args:
        request: The incoming `Request` object.
        exc: The `PasswordResetError` instance.

    Returns:
        A `JSONResponse` with a 400 status code and error detail.
    """
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": exc.message},
    )


async def email_service_error_handler(request: Request, exc: EmailServiceError) -> JSONResponse:
    """Handles `EmailServiceError`, returning a `503 Service Unavailable`.

    This indicates a problem with the external email sending service, preventing
    the application from sending emails.

    Args:
        request: The incoming `Request` object.
        exc: The `EmailServiceError` instance.

    Returns:
        A `JSONResponse` with a 503 status code and error detail.
    """
    logger.error(
        "Email service interaction failed",
        error_message=str(exc),
        client_ip=request.client.host,
        path=request.url.path,
    )
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": exc.message},
    )


async def user_not_found_error_handler(request: Request, exc: UserNotFoundError) -> JSONResponse:
    """Handles `UserNotFoundError`, returning a `404 Not Found`.

    This is triggered when an operation targets a user that does not exist in
    the database.

    Args:
        request: The incoming `Request` object.
        exc: The `UserNotFoundError` instance.

    Returns:
        A `JSONResponse` with a 404 status code and error detail.
    """
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": exc.message},
    )


async def cedrina_error_handler(request: Request, exc: CedrinaError) -> JSONResponse:
    """Handles the base `CedrinaError`, returning a `500 Internal Server Error`.

    This serves as a fallback for any custom application errors that do not
    have a more specific handler.

    Args:
        request: The incoming `Request` object.
        exc: The `CedrinaError` instance.

    Returns:
        A `JSONResponse` with a 500 status code and error detail.
    """
    logger.error(
        "An unhandled application error occurred",
        error_code=exc.code,
        error_message=exc.message,
        path=request.url.path,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected error occurred."},
    )


async def database_error_handler(request: Request, exc: DatabaseError) -> JSONResponse:
    """Handles `DatabaseError`, returning a `500 Internal Server Error`.

    This handler catches low-level database exceptions, abstracting the
    specific database error from the client.

    Args:
        request: The incoming `Request` object.
        exc: The `DatabaseError` instance.

    Returns:
        A `JSONResponse` with a 500 status code and a generic error message.
    """
    logger.critical(
        "A critical database error occurred",
        error_message=str(exc),
        path=request.url.path,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "A database error occurred."},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Registers all custom exception handlers with the FastAPI application.

    This function is called during application startup to ensure that all
    custom exceptions are handled gracefully and consistently. The order of
    registration matters, with more specific exceptions handled before
    more general ones.

    Args:
        app: The `FastAPI` application instance.
    """
    app.add_exception_handler(RateLimitExceeded, rate_limit_exception_handler)
    app.add_exception_handler(AuthenticationError, authentication_error_handler)
    app.add_exception_handler(PermissionError, permission_error_handler)
    app.add_exception_handler(DuplicateUserError, duplicate_user_error_handler)
    app.add_exception_handler(PasswordPolicyError, password_policy_error_handler)
    app.add_exception_handler(InvalidOldPasswordError, invalid_old_password_error_handler)
    app.add_exception_handler(PasswordReuseError, password_reuse_error_handler)
    app.add_exception_handler(
        PasswordValidationError, password_validation_error_handler
    )
    app.add_exception_handler(RateLimitExceededError, rate_limit_exceeded_error_handler)
    app.add_exception_handler(ForgotPasswordError, forgot_password_error_handler)
    app.add_exception_handler(PasswordResetError, password_reset_error_handler)
    app.add_exception_handler(EmailServiceError, email_service_error_handler)
    app.add_exception_handler(UserNotFoundError, user_not_found_error_handler)
    app.add_exception_handler(DatabaseError, database_error_handler)
    app.add_exception_handler(CedrinaError, cedrina_error_handler)
