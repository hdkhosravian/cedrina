from __future__ import annotations

"""
Global exception handlers for the FastAPI application.

This module contains centralized handlers for custom application exceptions,
translating them into appropriate HTTP responses.
"""

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette import status

from src.core.exceptions import (
    AuthenticationError,
    DuplicateUserError,
    PasswordPolicyError,
    PermissionError,
)

__all__ = [
    "authentication_error_handler",
    "duplicate_user_error_handler",
    "password_policy_error_handler",
    "permission_error_handler",
]


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


async def permission_error_handler(request: Request, exc: PermissionError):
    """
    Handles PermissionError exceptions, returning a 403 Forbidden response.
    """
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": str(exc)},
    ) 