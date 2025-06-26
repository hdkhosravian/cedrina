from __future__ import annotations

"""Request‐payload Pydantic models for authentication endpoints."""

from typing import Dict, Any, Literal

from pydantic import BaseModel, EmailStr, constr, Field
from src.core.config.settings import PASSWORD_MIN_LENGTH

# ---------------------------------------------------------------------------
# Shared / primitive types ---------------------------------------------------
# ---------------------------------------------------------------------------

UsernameStr = constr(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_-]+$")

# ---------------------------------------------------------------------------
# Shared password type -------------------------------------------------------
# ---------------------------------------------------------------------------

PasswordStr = constr(min_length=PASSWORD_MIN_LENGTH)

# ---------------------------------------------------------------------------
# Concrete request models ----------------------------------------------------
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    """Payload expected by ``POST /auth/register``."""

    username: UsernameStr = Field(..., examples=["john_doe"])
    email: EmailStr = Field(..., examples=["john@example.com"])
    password: PasswordStr = Field(..., examples=["Str0ngP@ssw0rd"])


class LoginRequest(BaseModel):
    """Payload expected by ``POST /auth/login``."""

    username: UsernameStr
    password: PasswordStr


class OAuthAuthenticateRequest(BaseModel):
    """Payload sent to ``POST /auth/oauth`` after client‐side token exchange."""

    provider: Literal["google", "microsoft", "facebook"]
    token: Dict[str, Any]


class ChangePasswordRequest(BaseModel):
    """Payload expected by ``POST /auth/change-password``."""

    current_password: PasswordStr
    new_password: PasswordStr
