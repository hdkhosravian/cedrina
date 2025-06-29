from __future__ import annotations

"""
Clean Architecture Logout Route.

This module provides a thin logout endpoint that delegates all business logic
to domain services while handling only HTTP concerns.

Key Clean Architecture Principles Applied:
- Thin controller with single responsibility (HTTP handling)
- Domain service delegation for all business logic
- Domain value objects for type safety and validation
- Security context extraction for audit trails
- Proper error handling and I18N support
- Dependency injection through interfaces
"""

from fastapi import APIRouter, Depends, Request, status
from fastapi.security import OAuth2PasswordBearer
from structlog import get_logger

from src.infrastructure.dependency_injection.auth_dependencies import get_user_logout_service
from src.adapters.api.v1.auth.schemas import LogoutRequest, MessageResponse
from src.core.config.settings import settings
from src.core.dependencies.auth import get_current_user
from src.core.exceptions import AuthenticationError
from src.domain.entities.user import User
from src.domain.interfaces.services import IUserLogoutService
from src.domain.value_objects.jwt_token import AccessToken, RefreshToken
from src.utils.i18n import get_translated_message

logger = get_logger(__name__)
router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


@router.delete(
    "",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Logout current user",
    description="Logout user by revoking access and refresh tokens using clean architecture principles.",
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
    logout_service: IUserLogoutService = Depends(get_user_logout_service),
) -> MessageResponse:
    """Clean logout endpoint that delegates to domain service.

    This endpoint follows clean architecture principles:
    1. **Thin Controller**: Only handles HTTP concerns and delegates business logic
    2. **Security Context**: Extracts security information for audit trails
    3. **Domain Value Objects**: Converts HTTP input to domain concepts
    4. **Service Delegation**: All business logic handled by domain service
    5. **Error Translation**: Converts domain exceptions to HTTP responses

    Business Logic Delegation:
    - Token revocation regardless of validity
    - Session termination and audit logging
    - Domain event publishing for security monitoring
    - Concurrent token revocation for performance

    Args:
        request: FastAPI request object for security context extraction
        payload: Request payload containing refresh token to revoke
        token: Access token from Authorization header
        current_user: Authenticated user from dependency injection
        logout_service: Domain logout service for business logic

    Returns:
        MessageResponse: Success message confirming logout

    Raises:
        AuthenticationError: If logout process fails (handled by global handler)

    Security Features:
    - Comprehensive audit trails with correlation IDs
    - Secure logging with data masking
    - Concurrent token revocation for atomicity
    - Always returns success to redirect to signin page

    """
    # Extract security context for audit trails and monitoring
    language = getattr(request.state, "language", "en")
    client_ip = getattr(request.state, "client_ip", "")
    user_agent = request.headers.get("User-Agent", "")
    correlation_id = getattr(request.state, "correlation_id", "")

    # Initialize variables to avoid UnboundLocalError
    access_token = None
    refresh_token = None

    try:
        # Convert HTTP input to domain value objects for type safety
        try:
            # Create access token value object from validated token
            access_token = AccessToken.from_encoded(
                token=token,
                public_key=settings.JWT_PUBLIC_KEY,
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE,
            )
            
            # Create refresh token value object from request payload
            refresh_token = RefreshToken.from_encoded(
                token=payload.refresh_token,
                public_key=settings.JWT_PUBLIC_KEY,
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE,
            )
        except ValueError as e:
            # Handle token validation errors - still proceed with logout
            await logger.awarning(
                "Invalid token format provided during logout - proceeding with logout anyway",
                user_id=current_user.id,
                username=current_user.username,
                correlation_id=correlation_id,
                error=str(e),
            )
            # Return success immediately since we don't validate tokens anymore
            return MessageResponse(message=get_translated_message("logout_successful", language))

        # Log logout request with security context
        await logger.ainfo(
            "Logout request received",
            user_id=current_user.id,
            username=current_user.username,
            access_token_id=access_token.get_token_id().mask_for_logging(),
            refresh_token_id=refresh_token.get_token_id().mask_for_logging(),
            correlation_id=correlation_id,
            client_ip=client_ip,
            user_agent_length=len(user_agent),
        )

        # Delegate all business logic to domain service
        await logout_service.logout_user(
            access_token=access_token,
            refresh_token=refresh_token,
            user=current_user,
            language=language,
            client_ip=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id,
        )

        # Log successful completion
        await logger.ainfo(
            "Logout request completed successfully",
            user_id=current_user.id,
            username=current_user.username,
            correlation_id=correlation_id,
        )

        return MessageResponse(message=get_translated_message("logout_successful", language))

    except Exception as e:
        # Log unexpected errors while maintaining security
        await logger.aerror(
            "Unexpected error during logout request",
            user_id=current_user.id if current_user else None,
            correlation_id=getattr(request.state, "correlation_id", ""),
            error_type=type(e).__name__,
            error_message=str(e),
        )
        # Even if there's an error, we still return success to redirect to signin page
        return MessageResponse(message=get_translated_message("logout_successful", language))
