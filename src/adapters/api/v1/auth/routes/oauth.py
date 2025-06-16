from __future__ import annotations

"""/auth/oauth route module.

This module handles authentication via external OAuth providers in the Cedrina authentication system.
It provides an endpoint for users to authenticate using OAuth tokens from providers like Google, Microsoft, and Facebook,
and issues JWT tokens for accessing protected resources.
"""

import secrets
from typing import Literal

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.responses import JSONResponse

from src.adapters.api.v1.auth.schemas import (
    OAuthAuthenticateRequest,
    OAuthAuthResponse,
    TokenPair,
    UserOut,
)
from src.adapters.api.v1.auth.dependencies import (
    get_oauth_service,
    get_token_service,
)
from src.domain.services.auth.oauth import OAuthService
from src.domain.services.auth.token import TokenService
from src.core.config.settings import settings
from src.core.exceptions import AuthenticationError

router = APIRouter()


@router.post(
    "",
    response_model=OAuthAuthResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Authenticate with OAuth provider",
    description="Authenticates a user using an OAuth token from an external provider (Google, Microsoft, Facebook). Issues JWT tokens upon successful authentication.",
)
async def oauth_authenticate(
    payload: OAuthAuthenticateRequest,
    oauth_service: OAuthService = Depends(get_oauth_service),
    token_service: TokenService = Depends(get_token_service),
):
    """
    Authenticate a user using an OAuth token from an external provider.

    Args:
        payload (OAuthAuthenticateRequest): The request payload containing the OAuth provider and token.
        oauth_service (OAuthService): The service for OAuth authentication operations.
        token_service (TokenService): The service for token operations.

    Returns:
        OAuthAuthResponse: A response containing the authenticated user's information, OAuth profile details, and JWT tokens.

    Raises:
        HTTPException: If OAuth authentication fails due to invalid or expired token.
    """
    user, profile = await oauth_service.authenticate_with_oauth(payload.provider, payload.token)

    access_token = await token_service.create_access_token(user=user)
    refresh_token = await token_service.create_refresh_token(user=user)

    token_type = "Bearer"
    return OAuthAuthResponse(
        user=UserOut.from_entity(user),
        provider=payload.provider,
        oauth_profile_id=profile.id if profile else None,
        tokens=TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type=token_type
        )
    ) 