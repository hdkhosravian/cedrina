from __future__ import annotations

"""/auth/register route module.

This module handles the registration of new users in the Cedrina authentication system.
It provides an endpoint for creating a new user account with a unique username and email,
and immediately issues JWT tokens for authentication upon successful registration.
"""

import secrets
from fastapi import APIRouter, Depends, status, HTTPException

from src.adapters.api.v1.auth.schemas import RegisterRequest, AuthResponse, TokenPair, UserOut
from src.adapters.api.v1.auth.dependencies import (
    get_user_auth_service,
    get_token_service,
)
from src.domain.services.auth.user_authentication import UserAuthenticationService
from src.domain.services.auth.token import TokenService
from src.core.config.settings import settings
from src.core.exceptions import DuplicateUserError, PasswordPolicyError

router = APIRouter()


@router.post(
    "",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["auth"],
    summary="Register a new user",
    description="Creates a new user account with the provided username, email, and password. Upon successful registration, issues JWT tokens for authentication.",
)
async def register_user(
    payload: RegisterRequest,
    user_service: UserAuthenticationService = Depends(get_user_auth_service),
    token_service: TokenService = Depends(get_token_service),
):
    """
    Register a new user with the provided credentials.

    Args:
        payload (RegisterRequest): The request payload containing user registration data.
        user_service (UserAuthenticationService): The service for user authentication operations.
        token_service (TokenService): The service for token operations.

    Returns:
        AuthResponse: A response containing the registered user's information and JWT tokens.

    Raises:
        HTTPException: If the registration fails due to duplicate username, weak password, or other validation errors.
    """
    user = await user_service.register_user(
        username=payload.username,
        email=payload.email,
        password=payload.password
    )

    access_token = await token_service.create_access_token(user=user)
    refresh_token = await token_service.create_refresh_token(user=user)

    token_type = "Bearer"
    return AuthResponse(
        tokens=TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type=token_type
        ),
        user=UserOut.from_entity(user)
    ) 