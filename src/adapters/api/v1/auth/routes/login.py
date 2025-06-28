from __future__ import annotations

"""/auth/login route module.

This module handles user authentication via username and password in the Cedrina
authentication system. It provides an endpoint for users to log in and receive
JWT tokens for accessing protected resources.
"""

from fastapi import APIRouter, Depends, Request, status

from src.adapters.api.v1.auth.dependencies import get_token_service, get_user_auth_service
from src.adapters.api.v1.auth.schemas import AuthResponse, LoginRequest, UserOut
from src.adapters.api.v1.auth.utils import create_token_pair
from src.domain.services.auth.token import TokenService
from src.domain.services.auth.user_authentication import UserAuthenticationService

router = APIRouter()


@router.post(
    "",
    response_model=AuthResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Authenticate a user",
    description="Authenticates a user with username and password, issuing JWT tokens on success.",
)
async def login_user(
    request: Request,
    payload: LoginRequest,
    user_service: UserAuthenticationService = Depends(get_user_auth_service),
    token_service: TokenService = Depends(get_token_service),
):
    """Authenticate a user with username and password.

    This endpoint validates user credentials and issues JWT tokens (access
    and refresh) for protected resources. It uses rate limiting to mitigate
    brute-force and credential stuffing attacks.

    Args:
        request (Request): FastAPI request object, used to get client IP for
            rate limiting.
        payload (LoginRequest): Request payload with username and password.
        user_service (UserAuthenticationService): Service for validating user
            credentials.
        token_service (TokenService): Service for generating JWT tokens.

    Returns:
        AuthResponse: Response with user details and JWT token pair.

    Raises:
        HTTPException: If credentials are invalid (401) or account inactive
            (403).

    Security:
        - Rate limiting uses username and client IP to prevent brute-force.
        - Enforced via slowapi middleware (see app config).
        - Passwords are hashed securely in user service (not route logic).
        - JWT tokens use RS256 signing for security (asymmetric keys).

    """
    # Rate limiting by username and client IP to mitigate credential stuffing.
    # Enforcement by slowapi middleware. If disabled, endpoint is vulnerable to
    # brute-force attacks.
    client_ip = request.client.host or "unknown"
    key = f"login:{payload.username}:{client_ip}"

    # Authenticate user. Raises error if credentials invalid or user inactive.
    user = await user_service.authenticate_by_credentials(payload.username, payload.password)

    # Create token pair using shared utility for consistency across endpoints.
    tokens = await create_token_pair(token_service, user)

    return AuthResponse(tokens=tokens, user=UserOut.from_entity(user))
