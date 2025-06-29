from __future__ import annotations

"""Authentication API schemas package.

This package splits the previously monolithic ``schemas.py`` into focused
modules that group *related* Pydantic models. Keeping the files small improves
readability, discoverability, and reduces the likelihood of circular imports.

We intentionally re-export **all** public symbols to preserve the original
``from src.adapters.api.v1.auth.schemas import …`` import-path used by routes
and tests.
"""

# flake8: noqa: F401 – re-export

from .misc import MessageResponse
from .requests import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    LogoutRequest,
    OAuthAuthenticateRequest,
    RegisterRequest,
    ResetPasswordRequest,
    UsernameStr,
)
from .responses.auth import AuthResponse, OAuthAuthResponse
from .responses.token import TokenPair
from .responses.user import UserOut

__all__ = [
    "RegisterRequest",
    "LoginRequest",
    "OAuthAuthenticateRequest",
    "LogoutRequest",
    "ChangePasswordRequest",
    "ForgotPasswordRequest",
    "ResetPasswordRequest",
    "UsernameStr",
    "UserOut",
    "TokenPair",
    "AuthResponse",
    "OAuthAuthResponse",
    "MessageResponse",
]
