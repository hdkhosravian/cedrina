from __future__ import annotations

"""Request‐payload Pydantic models for authentication endpoints."""

from typing import Dict, Any, Literal

from pydantic import BaseModel, EmailStr, constr, Field

# ---------------------------------------------------------------------------
# Shared / primitive types ---------------------------------------------------
# ---------------------------------------------------------------------------

UsernameStr = constr(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_-]+$")

# ---------------------------------------------------------------------------
# Concrete request models ----------------------------------------------------
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    """Payload expected by ``POST /auth/register``."""

    username: UsernameStr = Field(..., examples=["john_doe"])
    email: EmailStr = Field(..., examples=["john@example.com"])
    password: str = Field(..., examples=["Str0ngP@ssw0rd"])


class LoginRequest(BaseModel):
    """Payload expected by ``POST /auth/login``."""

    username: UsernameStr = Field(..., examples=["john_doe"])
    password: str = Field(..., examples=["Str0ngP@ssw0rd"])


class OAuthAuthenticateRequest(BaseModel):
    """Payload expected by ``POST /auth/oauth``."""

    provider: Literal["google", "microsoft", "facebook"] = Field(
        ..., examples=["google"]
    )
    token: str = Field(..., examples=["ya29.a0AfH6SMC..."])


class LogoutRequest(BaseModel):
    """Payload expected by ``DELETE /auth/logout``."""

    refresh_token: str = Field(..., examples=["eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."])


class ChangePasswordRequest(BaseModel):
    """Payload expected by ``PUT /auth/change-password``."""

    old_password: str = Field(..., examples=["OldPass123!"], description="Current password for verification")
    new_password: str = Field(..., examples=["NewPass456!"], description="New password that meets security policy requirements")
