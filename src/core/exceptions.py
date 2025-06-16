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

__all__: Final = [
    "CedrinaError",
    "AuthenticationError",
    "DatabaseError",
    "UserAlreadyExistsError",
    "InvalidCredentialsError",
    "PasswordPolicyError",
    "RateLimitError",
]


@dataclass(slots=True)
class CedrinaError(Exception):
    """Base exception for all domain-level errors in Cedrina."""

    message: str
    code: str = "error"

    # Dataclasses generate ``__init__``; hook into ``Exception`` to keep stack-trace.
    def __post_init__(self) -> None:  # noqa: D401
        # Call Exception.__init__ directly to avoid MRO edge-cases with `dataclass` subclasses.
        Exception.__init__(self, self.message)

    # A concise, structured representation used by loggers & FastAPI handlers.
    def __str__(self) -> str:  # noqa: D401
        return self.message


# ---------------------------------------------------------------------------
# Auth-related errors
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AuthenticationError(CedrinaError):
    """Raised for all authentication / authorisation failures."""

    code: str = "authentication_error"


@dataclass(slots=True)
class InvalidCredentialsError(AuthenticationError):
    """Raised when credentials supplied by the user are invalid."""

    code: str = "invalid_credentials"


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
    """Raised when a password fails to satisfy the configured policy."""

    code: str = "password_policy_failed"


# ---------------------------------------------------------------------------
# Operational errors
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class RateLimitError(CedrinaError):
    """Raised when a consumer exceeds the configured rate limits."""

    code: str = "rate_limit_exceeded"
    message: str = "Rate limit exceeded"