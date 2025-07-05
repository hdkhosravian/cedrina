from __future__ import annotations

"""Centralized, structured exception hierarchy for Cedrina.

This module defines a clear and comprehensive hierarchy of custom exceptions
for the application. Each exception is a slotted dataclass, ensuring they are
lightweight and efficient. They carry a machine-readable `code` for programmatic
error handling and a human-readable `message` for logging and user feedback.

The hierarchy is designed to:
- Provide clear, specific errors for different failure scenarios.
- Support internationalization (i18n) for user-facing messages.
- Map cleanly to HTTP status codes in the API layer.
- Offer a consistent structure for logging and monitoring.
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
    "EncryptionError",
    "DecryptionError",
    "EmailConfirmationError",
]


class CedrinaError(Exception):
    """Base exception class for all custom errors in the Cedrina application.

    This class serves as the root for all application-specific exceptions.
    It enforces the presence of a `message` and a `code`, ensuring that all
    errors are structured and identifiable.

    Attributes:
        message (str): A human-readable error message, suitable for logging.
                       This message can be translated.
        code (str): A unique, machine-readable error code for identifying
                    the type of error programmatically.
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


class AuthenticationError(CedrinaError):
    """Raised for general authentication failures.

    This exception is the base for more specific authentication-related
    errors. It typically maps to a `401 Unauthorized` HTTP status code.

    Attributes:
        message (str): A descriptive error message.
        code (str): An error code, defaults to "authentication_error".
    """

    def __init__(self, message: str, code: str = "authentication_error"):
        super().__init__(message, code)


class InvalidCredentialsError(AuthenticationError):
    """Raised specifically when user-provided credentials are invalid.

    This is a common error during login attempts. To prevent user enumeration,
    the message should be generic. Maps to a `401 Unauthorized` HTTP status.
    """

    def __init__(self, message: str, code: str = "invalid_credentials"):
        super().__init__(message, code)


class PermissionError(CedrinaError):
    """Raised when a user is not authorized to perform a specific action.

    This indicates that the user is authenticated but lacks the necessary
    permissions or roles for the requested resource. It maps to a
    `403 Forbidden` HTTP status code.
    """

    def __init__(self, message: str, code: str = "permission_denied"):
        super().__init__(message, code)


# ---------------------------------------------------------------------------
# Validation errors (typically map to 400 Bad Request)
# ---------------------------------------------------------------------------


class ValidationError(CedrinaError):
    """Raised for general data validation failures.

    This serves as a base for more specific validation errors and typically
    maps to a `400 Bad Request` or `422 Unprocessable Entity`.
    """

    def __init__(self, message: str, code: str = "validation_error"):
        super().__init__(message, code)


# ---------------------------------------------------------------------------
# Password validation errors (typically map to 400 Bad Request)
# ---------------------------------------------------------------------------


class PasswordValidationError(ValidationError):
    """Base exception for password validation failures.

    This is used for errors related to password rules that occur outside of the
    initial authentication flow (e.g., password change). It typically maps to a
    `400 Bad Request` HTTP status code.
    """

    def __init__(self, message: str, code: str = "password_validation_error"):
        super().__init__(message, code)


class InvalidOldPasswordError(PasswordValidationError):
    """Raised when the old password provided during a password change is incorrect.

    This ensures that only the legitimate user can change their password.
    It maps to a `400 Bad Request` status to avoid user enumeration.
    """

    def __init__(self, message: str, code: str = "invalid_old_password"):
        super().__init__(message, code)


class PasswordReuseError(PasswordValidationError):
    """Raised when a user attempts to reuse a recent password.

    This enforces a password history policy to improve security.
    It maps to a `400 Bad Request` HTTP status.
    """

    def __init__(self, message: str, code: str = "password_reuse_error"):
        super().__init__(message, code)


# ---------------------------------------------------------------------------
# Domain / persistence errors (typically map to 409 Conflict or 500 Server Error)
# ---------------------------------------------------------------------------


class DatabaseError(CedrinaError):
    """Raised for low-level database interaction errors.

    This exception wraps underlying database driver errors, abstracting away
    implementation details. It typically maps to a `500 Internal Server Error`
    HTTP status.
    """

    def __init__(self, message: str, code: str = "database_error"):
        super().__init__(message, code)


class UserAlreadyExistsError(CedrinaError):
    """Raised when attempting to create a user that already exists.

    This is commonly used during registration to signal a conflict with an
    existing username or email. It typically maps to a `409 Conflict` HTTP
    status code.
    """

    def __init__(self, message: str, code: str = "user_already_exists"):
        super().__init__(message, code)


class PasswordPolicyError(ValidationError):
    """Raised when a password does not meet the required security policy.

    This can include length, complexity, or other business rules. It is a form
    of validation error and typically maps to a `400 Bad Request`.
    """

    def __init__(self, message: str, code: str = "password_policy_error"):
        super().__init__(message, code)


# ---------------------------------------------------------------------------
# Operational errors (typically map to 429 Too Many Requests or 503 Service Unavailable)
# ---------------------------------------------------------------------------


class RateLimitError(CedrinaError):
    """Base class for rate limiting related errors.

    This exception and its subclasses map to a `429 Too Many Requests` HTTP
    status code.
    """

    def __init__(self, message: str | None = None, code: str = "rate_limit_exceeded"):
        if message is None:
            message = get_translated_message("rate_limit_exceeded", "en")
        super().__init__(message, code)


class RateLimitExceededError(RateLimitError):
    """Raised specifically when a rate limit has been exceeded.

    This indicates the user has made too many requests in a given time frame.
    It maps to a `429 Too Many Requests` HTTP status.
    """

    def __init__(self, message: str | None = None, code: str = "rate_limit_exceeded"):
        super().__init__(message, code)


class DuplicateUserError(UserAlreadyExistsError):
    """Raised when attempting to register a user with a username or email that already exists.

    This is a more specific version of `UserAlreadyExistsError` and maps to a
    `409 Conflict` HTTP status code.
    """

    def __init__(self, message: str, code: str = "duplicate_user_error"):
        super().__init__(message, code)


class EmailServiceError(CedrinaError):
    """Raised when there is an issue with the email sending service.

    This could be due to configuration issues, network problems, or provider
    outages. It typically maps to a `503 Service Unavailable` HTTP status.
    """

    def __init__(self, message: str, code: str = "email_service_error"):
        super().__init__(message, code)


class TemplateRenderError(EmailServiceError):
    """Raised when an email template fails to render.

    This indicates a problem with the template file itself, such as syntax
    errors or missing variables. It maps to a `500 Internal Server Error`.
    """

    def __init__(self, message: str, code: str = "template_render_error"):
        super().__init__(message, code)


class PasswordResetError(AuthenticationError):
    """Raised when password reset operations fail."""
    pass


class EmailConfirmationError(AuthenticationError):
    """Raised when email confirmation operations fail."""
    pass


class ForgotPasswordError(AuthenticationError):
    """Raised for failures during the "forgot password" request phase.

    This might occur if the user's email does not exist or if there are issues
    generating a reset token. It maps to a `400 Bad Request` or `404 Not Found`.
    """

    def __init__(self, message: str, code: str = "forgot_password_error"):
        super().__init__(message, code)


class UserNotFoundError(CedrinaError):
    """Raised when a requested user is not found in the database.

    This typically maps to a `404 Not Found` HTTP status code.
    """

    def __init__(self, message: str = "User not found", code: str = "user_not_found"):
        super().__init__(message, code)


class SessionLimitExceededError(AuthenticationError):
    """Raised when a user exceeds the maximum number of allowed active sessions.

    This is a security feature to prevent account abuse. It maps to a
    `401 Unauthorized` or `403 Forbidden` HTTP status.
    """

    def __init__(self, message: str, code: str = "session_limit_exceeded"):
        super().__init__(message, code)


# ---------------------------------------------------------------------------
# Cryptography-related errors
# ---------------------------------------------------------------------------


class EncryptionError(CedrinaError):
    """Raised when an encryption operation fails.

    This is a critical security failure and should be logged with high severity.
    It maps to a `500 Internal Server Error`.
    """

    message: str = "A critical error occurred during data encryption."
    code: str = "encryption_error"

    def __init__(self, message: str = "A critical error occurred during data encryption.", code: str = "encryption_error"):
        super().__init__(message, code)


class DecryptionError(CedrinaError):
    """Raised when a decryption operation fails.

    This could indicate data tampering or a key mismatch. It is a critical
    security failure. It maps to a `500 Internal Server Error`.
    """

    message: str = "A critical error occurred during data decryption."
    code: str = "decryption_error"

    def __init__(self, message: str = "A critical error occurred during data decryption.", code: str = "decryption_error"):
        super().__init__(message, code)
