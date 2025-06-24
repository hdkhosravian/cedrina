from __future__ import annotations

"""/auth/oauth route module.

This module handles authentication via external OAuth providers in the Cedrina
authentication system. It provides an endpoint for users to authenticate using
OAuth tokens from providers like Google, Microsoft, and Facebook, and issues JWT
tokens for accessing protected resources.
"""

from fastapi import APIRouter, Depends, status

from src.adapters.api.v1.auth.schemas import OAuthAuthenticateRequest, OAuthAuthResponse, UserOut
from src.adapters.api.v1.auth.dependencies import get_oauth_service, get_token_service
from src.adapters.api.v1.auth.utils import create_token_pair
from src.domain.services.auth.oauth import OAuthService
from src.domain.services.auth.token import TokenService

router = APIRouter()


@router.post(
    "",
    response_model=OAuthAuthResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Authenticate with OAuth provider",
    description="Authenticates a user using an OAuth token from a provider (Google, Microsoft, Facebook). Issues JWT tokens on success.",
)
async def oauth_authenticate(
    payload: OAuthAuthenticateRequest,
    oauth_service: OAuthService = Depends(get_oauth_service),
    token_service: TokenService = Depends(get_token_service),
):
    """
    Authenticate a user using an OAuth token from an external provider.

    This endpoint processes an OAuth token from a client-side authentication
    flow with providers like Google, Microsoft, or Facebook. It validates the
    token, links or creates a user account, and issues JWT tokens for internal
    authentication.

    Args:
        payload (OAuthAuthenticateRequest): Request payload with provider
            name and OAuth token.
        oauth_service (OAuthService): Service for validating OAuth tokens and
            managing profiles.
        token_service (TokenService): Service for generating internal JWT
            tokens.

    Returns:
        OAuthAuthResponse: Response with user details, provider info, OAuth
            profile ID (if applicable), and JWT token pair.

    Raises:
        HTTPException: If OAuth authentication fails due to invalid/expired
            token (401) or provider-specific errors (400).

    Security:
        - OAuth token validation (signature, expiration, issuer) is handled in
          OAuthService.
        - Ensure client-side token exchange follows provider best practices
          (e.g., PKCE for public clients).
        - Internal JWT tokens use RS256 signing for security (asymmetric keys).
        - No rate limiting applied; OAuth flows rely on provider limits. Add if
          abuse patterns emerge.
    """
    # Authenticate user with OAuth token and retrieve or create user/profile.
    # Raises error if token is invalid, expired, or provider rejects it.
    user, profile = await oauth_service.authenticate_with_oauth(payload.provider, payload.token)

    # Create token pair using shared utility for consistency across endpoints.
    tokens = await create_token_pair(token_service, user)

    return OAuthAuthResponse(
        user=UserOut.from_entity(user),
        provider=payload.provider,
        oauth_profile_id=profile.id if profile else None,
        tokens=tokens
    ) 