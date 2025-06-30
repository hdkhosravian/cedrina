from __future__ import annotations

"""Centralised, structured exception hierarchy for Cedrina.

This module defines *immutable* (slotted) dataclass–powered exceptions that carry a
machine-readable ``code`` attribute in addition to the human-friendly ``message``.

Rationale
---------
•  Dataclass exceptions remove repetitive ``__init__`` boiler-plate while retaining
   the ability to subclass easily.
•  ``slots=True`` keeps the memory-footprint minimal (exceptions are raised often
   on error paths).
•  Implementing ``__str__`` provides uniform logging / JSON serialisation across
   the entire application stack.
"""

from dataclasses import dataclass
from typing import Final

from src.utils.i18n import get_translated_message

__all__: Final = [
    "CedrinaError",
    "AuthenticationError",
    "DatabaseError",
    "UserAlreadyExistsError",
    "InvalidCredentialsError",
    "PasswordPolicyError",
    "RateLimitError",
    "RateLimitExceededError",
    "DuplicateUserError",
    "PermissionError",
    "PasswordValidationError",
    "InvalidOldPasswordError",
    "PasswordReuseError",
    "EmailServiceError",
    "TemplateRenderError",
    "PasswordResetError",
    "ForgotPasswordError",
    "UserNotFoundError",
    "ValidationError",
    "SessionLimitExceededError",
]


@dataclass(slots=True)
class CedrinaError(Exception):
    """Base exception class for all custom errors in the Cedrina application.

    Attributes:
        message (str): A human-readable error message.
        code (str): A unique error code for identifying the type of error.

    """

    message: str
    code: str = "generic_error"

    def __init__(self, message: str, code: str = "generic_error"):
        self.message = message
        self.code = code
        Exception.__init__(self, self.message)

    # A concise, structured representation used by loggers & FastAPI handlers.
    def __str__(self) -> str:
        return self.message


# ---------------------------------------------------------------------------
# Auth-related errors
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AuthenticationError(CedrinaError):
    """Exception raised when authentication fails.

    This can occur due to invalid credentials, inactive accounts, or expired tokens.
    """

    def __init__(self, message: str, code: str = "authentication_error"):
        CedrinaError.__init__(self, message, code)


@dataclass(slots=True)
class InvalidCredentialsError(AuthenticationError):
    """Raised when credentials supplied by the user are invalid."""

    code: str = "invalid_credentials"


@dataclass(slots=True)
class PermissionError(CedrinaError):
    """Exception raised when a user is not authorized to perform an action."""

    def __init__(self, message: str, code: str = "permission_denied"):
        CedrinaError.__init__(self, message, code)


# ---------------------------------------------------------------------------
# Password validation errors (400 status code)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class PasswordValidationError(CedrinaError):
    """Exception raised when password validation fails during change password operations.

    This should return 400 status code, not 401, to avoid redirecting users to login.
    """

    def __init__(self, message: str, code: str = "password_validation_error"):
        CedrinaError.__init__(self, message, code)


@dataclass(slots=True)
class InvalidOldPasswordError(PasswordValidationError):
    """Exception raised when the old password provided during password change is incorrect.

    This should return 400 status code, not 401, to avoid redirecting users to login.
    """

    def __init__(self, message: str, code: str = "invalid_old_password"):
        PasswordValidationError.__init__(self, message, code)


@dataclass(slots=True)
class PasswordReuseError(PasswordValidationError):
    """Exception raised when the new password is the same as the old password.

    This should return 400 status code, not 401, to avoid redirecting users to login.
    """

    def __init__(self, message: str, code: str = "password_reuse_error"):
        PasswordValidationError.__init__(self, message, code)


# ---------------------------------------------------------------------------
# Domain / persistence errors
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class DatabaseError(CedrinaError):
    """Raised for low-level database interaction errors."""

    code: str = "database_error"


@dataclass(slots=True)
class UserAlreadyExistsError(CedrinaError):
    """Raised when attempting to create a user that already exists."""

    code: str = "user_already_exists"


@dataclass(slots=True)
class PasswordPolicyError(CedrinaError):
    """Exception raised when a password does not meet the required security policy."""

    def __init__(self, message: str, code: str = "password_policy_error"):
        CedrinaError.__init__(self, message, code)


# ---------------------------------------------------------------------------
# Operational errors
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class RateLimitError(CedrinaError):
    """Raised when a consumer exceeds the configured rate limits."""

    def __init__(self, message: str | None = None, code: str = "rate_limit_exceeded"):
        if message is None:
            message = get_translated_message("rate_limit_exceeded", "en")
        CedrinaError.__init__(self, message, code)


@dataclass(slots=True)
class RateLimitExceededError(RateLimitError):
    """Exception raised when a consumer exceeds the configured rate limits."""

    def __init__(self, message: str | None = None, code: str = "rate_limit_exceeded"):
        if message is None:
            message = get_translated_message("rate_limit_exceeded", "en")
        CedrinaError.__init__(self, message, code)


@dataclass(slots=True)
class DuplicateUserError(CedrinaError):
    """Exception raised when attempting to register a user with a username or email that already exists."""

    def __init__(self, message: str, code: str = "duplicate_user_error"):
        CedrinaError.__init__(self, message, code)


# ---------------------------------------------------------------------------
# Email service errors
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class EmailServiceError(CedrinaError):
    """Exception raised when email service operations fail."""

    def __init__(self, message: str, code: str = "email_service_error"):
        CedrinaError.__init__(self, message, code)


@dataclass(slots=True)
class TemplateRenderError(EmailServiceError):
    """Exception raised when email template rendering fails."""

    def __init__(self, message: str, code: str = "template_render_error"):
        EmailServiceError.__init__(self, message, code)


@dataclass(slots=True)
class PasswordResetError(CedrinaError):
    """Exception raised when password reset operations fail."""

    def __init__(self, message: str, code: str = "password_reset_error"):
        CedrinaError.__init__(self, message, code)


@dataclass(slots=True)
class ForgotPasswordError(CedrinaError):
    """Exception raised when a forgot password operation fails."""

    def __init__(self, message: str, code: str = "forgot_password_error"):
        CedrinaError.__init__(self, message, code)


@dataclass(slots=True)
class UserNotFoundError(CedrinaError):
    """Exception raised when a requested user is not found."""

    def __init__(self, message: str, code: str = "user_not_found"):
        CedrinaError.__init__(self, message, code)


@dataclass(slots=True)
class ValidationError(CedrinaError):
    """Exception raised when input validation fails."""

    def __init__(self, message: str, code: str = "validation_error"):
        CedrinaError.__init__(self, message, code)


@dataclass(slots=True)
class SessionLimitExceededError(CedrinaError):
    """Exception raised when a session limit is exceeded."""

    def __init__(self, message: str, code: str = "session_limit_exceeded"):
        CedrinaError.__init__(self, message, code)
