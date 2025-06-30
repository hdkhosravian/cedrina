"""OAuth endpoint module with enhanced security logging and information disclosure prevention.

This module handles user authentication via external OAuth providers using clean architecture
principles with enterprise-grade security features. The API layer is kept thin with no 
business logic - all OAuth logic is delegated to domain services.

Key Security Features:
- Zero-trust data masking for audit trails
- Consistent error responses to prevent enumeration attacks
- Standardized timing to prevent timing attacks
- Comprehensive security event logging with SIEM integration
- Risk-based OAuth authentication analysis and threat detection
- Privacy-compliant data handling (GDPR)
- OAuth token security validation and monitoring

Key DDD Principles Applied:
- Thin API layer with no business logic
- Domain value objects for input validation
- Domain services for business logic
- Domain events for audit trails
- Proper separation of concerns
- Security context capture for audit trails
- Correlation ID tracking for request tracing
- I18N support for error messages
"""

import uuid
from typing import Any, Dict

import structlog
from fastapi import APIRouter, Depends, Request, status

from src.infrastructure.dependency_injection.auth_dependencies import (
    CleanOAuthService,
    CleanTokenService,
)
from src.adapters.api.v1.auth.schemas import OAuthAuthResponse, OAuthAuthenticateRequest, UserOut
from src.core.exceptions import AuthenticationError
from src.domain.interfaces.services import IOAuthService, ITokenService
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.domain.value_objects.oauth_provider import OAuthProvider
from src.domain.value_objects.oauth_token import OAuthToken
from src.utils.i18n import get_request_language, get_translated_message

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post(
    "",
    response_model=OAuthAuthResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Authenticate with OAuth provider",
    description=(
        "Authenticates a user using an OAuth token from a provider (Google, Microsoft, Facebook) "
        "using Domain-Driven Design principles. This endpoint follows clean architecture with "
        "no business logic in the API layer. All OAuth logic is handled by domain services "
        "with proper value objects, domain events, and security context capture."
    ),
)
async def oauth_authenticate(
    request: Request,
    payload: OAuthAuthenticateRequest,
    oauth_service: IOAuthService = Depends(CleanOAuthService),
    token_service: ITokenService = Depends(CleanTokenService),
):
    """Authenticate a user using an OAuth token from an external provider using DDD principles.

    This endpoint implements a thin API layer that follows Domain-Driven Design
    and clean architecture principles:
    
    1. **No Business Logic**: All OAuth logic is delegated to domain services
    2. **Domain Value Objects**: Uses OAuthProvider and OAuthToken value objects for validation
    3. **Security Context**: Captures client IP, user agent, and correlation ID
    4. **Domain Events**: OAuth events are published by domain services
    5. **Clean Error Handling**: Proper handling of domain exceptions
    6. **Secure Logging**: Implements data masking and correlation tracking
    7. **I18N Support**: All error messages are internationalized
    
    OAuth Flow:
    1. Extract security context from request (IP, User-Agent)
    2. Generate correlation ID for request tracing
    3. Create domain value objects for input validation
    4. Delegate OAuth authentication to domain service
    5. Create JWT tokens using token service
    6. Return clean response with user data and tokens

    Args:
        request (Request): FastAPI request object for security context extraction
        payload (OAuthAuthenticateRequest): OAuth credentials from request body
        oauth_service (IOAuthService): Domain OAuth service
        token_service (ITokenService): Domain token service

    Returns:
        OAuthAuthResponse: User details, provider info, OAuth profile ID, and JWT tokens

    Raises:
        HTTPException: OAuth authentication failures with appropriate status codes

    Security Features:
        - Value object validation for OAuth providers and tokens
        - Comprehensive audit trails via domain events
        - Attack pattern detection and logging
        - Secure logging with data masking
        - Correlation ID tracking for request tracing
        - Security context capture (IP, User-Agent) for audit trails
        - I18N support for error messages
    """
    # Generate correlation ID for request tracking and debugging
    correlation_id = str(uuid.uuid4())
    
    # Extract security context from request for audit trails
    client_ip = request.client.host or "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Extract language from request for I18N
    language = get_request_language(request)
    
    # Create structured logger with correlation context and security information
    request_logger = logger.bind(
        correlation_id=correlation_id,
        client_ip=secure_logging_service.mask_ip_address(client_ip),
        user_agent=secure_logging_service.sanitize_user_agent(user_agent),
        endpoint="oauth",
        operation="oauth_authentication"
    )
    
    # Log OAuth authentication attempt initiation with secure data masking
    request_logger.info(
        "OAuth authentication attempt initiated",
        provider=payload.provider,
        has_token=bool(payload.token),
        security_context_captured=True,
        security_enhanced=True
    )
    
    try:
        # Create domain value objects for input validation and normalization
        # This is the only validation done in the API layer - all business logic
        # is delegated to domain services
        provider = OAuthProvider.create_safe(payload.provider)
        token = OAuthToken.create_safe(payload.token)
        
        request_logger.debug(
            "Domain value objects created successfully",
            provider=provider.mask_for_logging(),
            token_info=token.mask_for_logging(),
            security_enhanced=True
        )
        
        # Delegate OAuth authentication to domain service
        # The domain service handles all business logic including:
        # - OAuth token validation and expiration checking
        # - ID token validation for OpenID Connect providers
        # - User information fetching from OAuth provider
        # - User creation or linking with existing accounts
        # - OAuth profile management
        # - Domain event publishing
        # - Security monitoring and audit trails
        user, oauth_profile = await oauth_service.authenticate_with_oauth(
            provider=provider,
            token=token,
            language=language,
            client_ip=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id,
        )
        
        request_logger.info(
            "User authenticated successfully via OAuth by enhanced domain service",
            user_id=user.id,
            provider=provider.mask_for_logging(),
            authentication_method="oauth",
            security_enhanced=True
        )

        # Create JWT tokens using domain token service
        # This service handles token generation, signing, and expiration
        tokens = await token_service.create_token_pair(user)
        
        request_logger.info(
            "OAuth authentication tokens created successfully",
            user_id=user.id,
            token_type=tokens.get("token_type", "bearer"),
            expires_in=tokens.get("expires_in", 900),
            refresh_token_provided="refresh_token" in tokens,
            security_enhanced=True
        )
        
        # Return clean response using domain entity
        # The response is constructed from the domain entity, ensuring
        # consistency between domain model and API response
        return OAuthAuthResponse(
            user=UserOut.from_entity(user),
            provider=payload.provider,
            oauth_profile_id=oauth_profile.id if oauth_profile else None,
            tokens=tokens,
        )
        
    except ValueError as e:
        # Handle value object validation errors with standardized response
        # These occur when input format is invalid (e.g., invalid provider, expired token)
        request_logger.warning(
            "OAuth authentication failed - invalid input format",
            error=str(e),
            error_type="validation_error",
            provider_provided=payload.provider,
            has_token=bool(payload.token),
            security_enhanced=True
        )
        
        # Use error standardization service for consistent response
        standardized_response = await error_standardization_service.create_standardized_response(
            error_type="invalid_input",
            actual_error=str(e),
            correlation_id=correlation_id,
            language=language
        )
        raise AuthenticationError(message=standardized_response["detail"])
        
    except AuthenticationError as e:
        # Handle domain OAuth errors with enhanced logging
        # These are raised by the domain service for business rule violations
        # (e.g., invalid token, provider errors, inactive user)
        request_logger.warning(
            "OAuth authentication failed - enhanced domain error",
            error=str(e),
            error_type="oauth_authentication_error",
            provider=provider.mask_for_logging() if 'provider' in locals() else "unknown",
            security_enhanced=True
        )
        # Re-raise to maintain proper HTTP status codes and error context
        raise
        
    except Exception as e:
        # Handle unexpected errors with enhanced security logging
        # These should not occur in normal operation and indicate system issues
        request_logger.error(
            "OAuth authentication failed - unexpected error",
            error=str(e),
            error_type=type(e).__name__,
            provider=provider.mask_for_logging() if 'provider' in locals() else "unknown",
            security_enhanced=True
        )
        
        # Use error standardization service for consistent response
        standardized_response = await error_standardization_service.create_standardized_response(
            error_type="invalid_input",
            actual_error=str(e),
            correlation_id=correlation_id,
            language=language
        )
        raise AuthenticationError(message=standardized_response["detail"])
