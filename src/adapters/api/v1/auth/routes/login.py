from __future__ import annotations

"""/auth/login route module.

This module handles user authentication via username and password in the Cedrina authentication system.
It provides an endpoint for users to log in and receive JWT tokens for accessing protected resources.
"""

import secrets
from fastapi import APIRouter, Depends, status, HTTPException

from src.adapters.api.v1.auth.schemas import LoginRequest, AuthResponse, TokenPair, UserOut
from src.adapters.api.v1.auth.dependencies import (
    get_user_auth_service,
    get_token_service,
)
from src.domain.services.auth.user_authentication import UserAuthenticationService
from src.domain.services.auth.token import TokenService
from src.core.config.settings import settings
from src.core.exceptions import AuthenticationError

router = APIRouter()


@router.post(
    "",
    response_model=AuthResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Authenticate a user",
    description="Authenticates a user with the provided username and password, issuing JWT tokens upon successful authentication.",
)
async def login_user(
    payload: LoginRequest,
    user_service: UserAuthenticationService = Depends(get_user_auth_service),
    token_service: TokenService = Depends(get_token_service),
):
    """
    Authenticate a user with username and password.

    Args:
        payload (LoginRequest): The request payload containing user login credentials.
        user_service (UserAuthenticationService): The service for user authentication operations.
        token_service (TokenService): The service for token operations.

    Returns:
        AuthResponse: A response containing the authenticated user's information and JWT tokens.

    Raises:
        HTTPException: If authentication fails due to invalid credentials or inactive account.
    """
    user = await user_service.authenticate_by_credentials(payload.username, payload.password)

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