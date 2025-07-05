from __future__ import annotations

"""Request‐payload Pydantic models for authentication endpoints."""

from typing import Any, Dict, Literal

from pydantic import BaseModel, EmailStr, Field, constr

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

    provider: Literal["google", "microsoft", "facebook"] = Field(..., examples=["google"])
    token: Dict[str, Any] = Field(
        ..., examples=[{"access_token": "ya29.a0AfH6SMC...", "expires_at": 1640995200}]
    )


class LogoutRequest(BaseModel):
    """Payload expected by ``DELETE /auth/logout``."""

    refresh_token: str = Field(..., examples=["eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."])


class ChangePasswordRequest(BaseModel):
    """Payload expected by ``PUT /auth/change-password``."""

    old_password: str = Field(
        ..., examples=["OldPass123!"], description="Current password for verification"
    )
    new_password: str = Field(
        ...,
        examples=["NewPass456!"],
        description="New password that meets security policy requirements",
    )


class ForgotPasswordRequest(BaseModel):
    """Payload expected by ``POST /auth/forgot-password``."""

    email: EmailStr = Field(
        ..., 
        examples=["john@example.com"],
        description="Email address to send password reset instructions to"
    )


class ResetPasswordRequest(BaseModel):
    """Payload expected by ``POST /auth/reset-password``."""

    token: str = Field(
        ...,
        examples=["a1b2c3d4e5f6..."],
        description="Password reset token received via email",
        min_length=64,
        max_length=64
    )
    new_password: str = Field(
        ...,
        examples=["NewSecurePass123!"],
        description="New password that meets security policy requirements"
    )


class ResendConfirmationRequest(BaseModel):
    email: EmailStr
