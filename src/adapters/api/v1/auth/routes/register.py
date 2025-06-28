from __future__ import annotations

"""/auth/register route module.

This module handles the registration of new users in the Cedrina authentication
system. It provides an endpoint for creating a new user account with a unique
username and email, and issues JWT tokens on successful registration.
"""

from fastapi import APIRouter, Depends, Request, status

from src.adapters.api.v1.auth.dependencies import get_token_service, get_user_auth_service
from src.adapters.api.v1.auth.schemas import AuthResponse, RegisterRequest, UserOut
from src.adapters.api.v1.auth.utils import create_token_pair
from src.domain.services.auth.token import TokenService
from src.domain.services.auth.user_authentication import UserAuthenticationService

router = APIRouter()


@router.post(
    "",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["auth"],
    summary="Register a new user",
    description="Creates a new user account with username, email, and password. Issues JWT tokens on success.",
)
async def register_user(
    request: Request,
    payload: RegisterRequest,
    user_service: UserAuthenticationService = Depends(get_user_auth_service),
    token_service: TokenService = Depends(get_token_service),
):
    """Register a new user with the provided credentials.

    This endpoint creates a user account after validating data (username
    uniqueness, email format, password strength). On success, it issues JWT
    tokens for authentication. Rate limiting prevents abuse.

    Args:
        request (Request): FastAPI request object, used to get client IP for
            rate limiting.
        payload (RegisterRequest): Request payload with username, email, and
            password.
        user_service (UserAuthenticationService): Service for user creation and
            validation.
        token_service (TokenService): Service for generating JWT tokens.

    Returns:
        AuthResponse: Response with registered user's details and JWT token
            pair.

    Raises:
        HTTPException: If registration fails due to duplicate username/email
            (409), weak password (400), or validation errors (400).

    Security:
        - Rate limiting by client IP prevents bulk registration attacks.
        - Enforced via slowapi middleware (see app config).
        - Passwords hashed securely in user service (not route logic).
        - JWT tokens use RS256 signing for security (asymmetric keys).

    """
    # Rate limiting by client IP to prevent bulk registration abuse. Enforcement
    # by slowapi middleware. If disabled, endpoint is vulnerable to abuse.
    client_ip = request.client.host or "unknown"
    key = f"register:{client_ip}"
    # Manual enforcement removed as it's handled by middleware.
    # await enforce_rate_limit(token_service.redis_client, key)

    # Register user. Raises exceptions if validation fails (e.g., duplicate user,
    # weak password).
    user = await user_service.register_user(
        username=payload.username, email=payload.email, password=payload.password
    )

    # Create token pair using shared utility for consistency across endpoints.
    tokens = await create_token_pair(token_service, user)

    return AuthResponse(tokens=tokens, user=UserOut.from_entity(user))
