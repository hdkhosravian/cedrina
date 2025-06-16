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

from .requests import RegisterRequest, LoginRequest, OAuthAuthenticateRequest, UsernameStr
from .responses.user import UserOut
from .responses.token import TokenPair
from .responses.auth import AuthResponse, OAuthAuthResponse
from .misc import MessageResponse

__all__ = [
    "RegisterRequest",
    "LoginRequest",
    "OAuthAuthenticateRequest",
    "UsernameStr",
    "UserOut",
    "TokenPair",
    "AuthResponse",
    "OAuthAuthResponse",
    "MessageResponse",
] 