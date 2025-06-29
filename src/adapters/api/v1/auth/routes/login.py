"""Login endpoint module following Domain-Driven Design principles.

This module handles user authentication via username and password using clean architecture
principles. The API layer is kept thin with no business logic - all authentication logic
is delegated to domain services.

Key DDD Principles Applied:
- Thin API layer with no business logic
- Domain value objects for input validation
- Domain services for business logic
- Domain events for audit trails
- Proper separation of concerns
- Security context capture for audit trails
- Correlation ID tracking for request tracing

The endpoint follows clean architecture by:
1. Extracting security context from request
2. Creating domain value objects for validation
3. Delegating authentication to domain service
4. Handling domain exceptions appropriately
5. Returning clean response objects
6. Implementing secure logging with data masking
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, Request, status

from src.infrastructure.dependency_injection.auth_dependencies import (
    CleanAuthService,
    CleanTokenService,
)
from src.adapters.api.v1.auth.schemas import AuthResponse, LoginRequest, UserOut
from src.core.exceptions import AuthenticationError
from src.domain.interfaces.services import ITokenService, IUserAuthenticationService
from src.domain.value_objects.password import Password
from src.domain.value_objects.username import Username
from src.utils.i18n import get_request_language, get_translated_message

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post(
    "",
    response_model=AuthResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Authenticate a user",
    description=(
        "Authenticates a user with username and password using Domain-Driven Design principles. "
        "This endpoint follows clean architecture with no business logic in the API layer. "
        "All authentication logic is handled by domain services with proper value objects, "
        "domain events, and security context capture."
    ),
)
async def login_user(
    request: Request,
    payload: LoginRequest,
    auth_service: IUserAuthenticationService = Depends(CleanAuthService),
    token_service: ITokenService = Depends(CleanTokenService),
):
    """Authenticate a user with username and password using DDD principles.

    This endpoint implements a thin API layer that follows Domain-Driven Design
    and clean architecture principles:
    
    1. **No Business Logic**: All authentication logic is delegated to domain services
    2. **Domain Value Objects**: Uses Username and Password value objects for validation
    3. **Security Context**: Captures client IP, user agent, and correlation ID
    4. **Domain Events**: Authentication events are published by domain services
    5. **Clean Error Handling**: Proper handling of domain exceptions
    6. **Secure Logging**: Implements data masking and correlation tracking
    
    Authentication Flow:
    1. Extract security context from request (IP, User-Agent)
    2. Generate correlation ID for request tracing
    3. Create domain value objects for input validation
    4. Delegate authentication to domain service
    5. Create JWT tokens using token service
    6. Return clean response with user data and tokens

    Args:
        request (Request): FastAPI request object for security context extraction
        payload (LoginRequest): User credentials from request body
        auth_service (IUserAuthenticationService): Domain authentication service
        token_service (ITokenService): Domain token service

    Returns:
        AuthResponse: User details and JWT tokens

    Raises:
        HTTPException: Authentication failures with appropriate status codes

    Security Features:
        - Value object validation for usernames and passwords
        - Timing attack protection via constant-time operations
        - Comprehensive audit trails via domain events
        - Attack pattern detection and logging
        - Secure logging with data masking
        - Correlation ID tracking for request tracing
        - Security context capture (IP, User-Agent) for audit trails
    """
    # Generate correlation ID for request tracking and debugging
    correlation_id = str(uuid.uuid4())
    
    # Extract security context from request for audit trails
    client_ip = request.client.host or "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Create structured logger with correlation context and security information
    request_logger = logger.bind(
        correlation_id=correlation_id,
        client_ip=client_ip[:15] + "***" if len(client_ip) > 15 else client_ip,
        user_agent=user_agent[:50] + "***" if len(user_agent) > 50 else user_agent,
        endpoint="login",
        operation="user_authentication"
    )
    
    # Log authentication attempt initiation
    request_logger.info(
        "Login attempt initiated",
        username_length=len(payload.username),
        has_password=bool(payload.password),
        security_context_captured=True
    )
    
    try:
        # Create domain value objects for input validation and normalization
        # This is the only validation done in the API layer - all business logic
        # is delegated to domain services
        username = Username(payload.username)
        password = Password(payload.password)
        
        # Extract language from request for I18N
        language = get_request_language(request)
        
        request_logger.debug(
            "Domain value objects created successfully",
            username_normalized=username.mask_for_logging(),
            password_validated=True
        )
        
        # Delegate authentication to domain service
        # The domain service handles all business logic including:
        # - User lookup and password verification
        # - Account status validation
        # - Domain event publishing
        # - Security monitoring and audit trails
        user = await auth_service.authenticate_user(
            username=username,
            password=password,
            language=language,
            client_ip=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id,
        )
        
        request_logger.info(
            "User authenticated successfully by domain service",
            user_id=user.id,
            username=username.mask_for_logging(),
            authentication_method="username_password"
        )

        # Create JWT tokens using domain token service
        # This service handles token generation, signing, and expiration
        tokens = await token_service.create_token_pair(user)
        
        request_logger.info(
            "Authentication tokens created successfully",
            user_id=user.id,
            token_type=tokens.get("token_type", "bearer"),
            expires_in=tokens.get("expires_in", 900),
            refresh_token_provided="refresh_token" in tokens
        )
        
        # Return clean response using domain entity
        # The response is constructed from the domain entity, ensuring
        # consistency between domain model and API response
        return AuthResponse(
            tokens=tokens,
            user=UserOut.from_entity(user)
        )
        
    except ValueError as e:
        # Handle value object validation errors
        # These occur when input format is invalid (e.g., empty username)
        request_logger.warning(
            "Authentication failed - invalid input format",
            error=str(e),
            error_type="validation_error",
            username_provided=bool(payload.username),
            password_provided=bool(payload.password)
        )
        raise AuthenticationError(
            message=get_translated_message("invalid_username_or_password", language)
        )
        
    except AuthenticationError as e:
        # Handle domain authentication errors
        # These are raised by the domain service for business rule violations
        # (e.g., invalid credentials, inactive account)
        request_logger.warning(
            "Authentication failed - domain error",
            error=str(e),
            error_type="authentication_error",
            username=username.mask_for_logging() if 'username' in locals() else "unknown"
        )
        # Re-raise to maintain proper HTTP status codes and error context
        raise
        
    except Exception as e:
        # Handle unexpected errors
        # These should not occur in normal operation and indicate system issues
        request_logger.error(
            "Authentication failed - unexpected error",
            error=str(e),
            error_type=type(e).__name__,
            username=username.mask_for_logging() if 'username' in locals() else "unknown"
        )
        # Return generic error to prevent information leakage
        raise AuthenticationError(
            message=get_translated_message("authentication_service_unavailable", language)
        )
