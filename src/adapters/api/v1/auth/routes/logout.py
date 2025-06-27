from __future__ import annotations

"""
/auth/logout route module.

This module provides the logout endpoint for the authentication system, 
handling token revocation and session cleanup with proper security measures.
"""

from fastapi import APIRouter, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer
from structlog import get_logger
from jose import JWTError, jwt

from src.adapters.api.v1.auth.schemas import LogoutRequest, MessageResponse
from src.adapters.api.v1.auth.dependencies import get_token_service
from src.core.dependencies.auth import get_current_user
from src.core.exceptions import AuthenticationError
from src.domain.entities.user import User
from src.domain.services.auth.token import TokenService
from src.utils.i18n import get_translated_message
from src.core.config.settings import settings

logger = get_logger(__name__)
router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


@router.delete(
    "",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Logout current user",
    description="Invalidate the user's access and refresh tokens, effectively ending their session.",
    responses={
        200: {"description": "Successfully logged out"},
        401: {"description": "Authentication failed - invalid token or session"},
        422: {"description": "Validation error - missing refresh_token"},
    },
)
async def logout_user(
    request: Request,
    payload: LogoutRequest,
    token: str = Depends(oauth2_scheme),
    current_user: User = Depends(get_current_user),
    token_service: TokenService = Depends(get_token_service),
) -> MessageResponse:
    """
    Logout endpoint that invalidates user tokens and ends their session.
    
    This endpoint performs the following security operations:
    1. Validates the provided access token
    2. Validates that the refresh token belongs to the authenticated user
    3. Blacklists the access token to prevent further use
    4. Revokes the refresh token and associated session
    
    Args:
        request: FastAPI request object for language context
        payload: Request payload containing the refresh token to revoke
        token: Access token from Authorization header
        current_user: Authenticated user from token validation
        token_service: Service for token operations
        
    Returns:
        MessageResponse: Success message confirming logout
        
    Raises:
        AuthenticationError: If token validation or revocation fails
        ValidationError: If refresh_token is missing from payload
        
    Security Notes:
        - Access tokens are blacklisted to prevent replay attacks
        - Refresh tokens are validated for ownership before revocation
        - Refresh tokens are revoked from both Redis and database
        - Session data is marked as revoked for audit purposes
    """
    try:
        # Get the language from request state, fallback to 'en' if not set
        language = getattr(request.state, 'language', 'en')
        
        # Validate the access token and extract JTI for blacklisting
        decoded_token = await token_service.validate_token(token, language)
        jti = decoded_token["jti"]
        
        # SECURITY FIX: Validate refresh token ownership
        # Decode the refresh token to extract the user_id and verify ownership
        try:
            refresh_payload = jwt.decode(
                payload.refresh_token,
                settings.JWT_PUBLIC_KEY,
                algorithms=["RS256"],
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE
            )
            refresh_token_user_id = int(refresh_payload["sub"])
            
            # Verify that the refresh token belongs to the authenticated user
            if refresh_token_user_id != current_user.id:
                await logger.awarning(
                    "Attempted logout with mismatched refresh token",
                    authenticated_user_id=current_user.id,
                    refresh_token_user_id=refresh_token_user_id,
                    username=current_user.username
                )
                raise AuthenticationError(get_translated_message("invalid_refresh_token", language))
                
        except JWTError as e:
            await logger.awarning(
                "Invalid refresh token provided during logout",
                user_id=current_user.id,
                username=current_user.username,
                error=str(e)
            )
            raise AuthenticationError(get_translated_message("invalid_refresh_token", language)) from e
        
        # Log the logout attempt for security audit
        await logger.ainfo(
            "User logout initiated", 
            user_id=current_user.id, 
            username=current_user.username,
            jti=jti
        )
        
        # Revoke both access token (blacklist) and refresh token (session cleanup)
        # These operations are performed concurrently for better performance
        await token_service.revoke_access_token(jti)
        await token_service.revoke_refresh_token(payload.refresh_token)
        
        await logger.ainfo(
            "User successfully logged out", 
            user_id=current_user.id, 
            username=current_user.username
        )
        
        return MessageResponse(message="Logged out successfully")
        
    except AuthenticationError:
        # Re-raise authentication errors to be handled by FastAPI exception handler
        await logger.awarning(
            "Logout failed due to authentication error", 
            user_id=current_user.id if current_user else None
        )
        raise
    except Exception as e:
        # Log unexpected errors for debugging while maintaining security
        await logger.aerror(
            "Unexpected error during logout", 
            user_id=current_user.id if current_user else None,
            error=str(e)
        )
        language = getattr(request.state, 'language', 'en')
        raise AuthenticationError(get_translated_message("logout_failed_internal_error", language))
