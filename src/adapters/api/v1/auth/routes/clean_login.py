"""Clean Architecture Login Endpoint.

This module provides a clean implementation of user authentication following
Domain-Driven Design principles and clean architecture patterns.
"""

from __future__ import annotations

import uuid

import structlog
from fastapi import APIRouter, Depends, Request, status

from src.adapters.api.v1.auth.clean_dependencies import (
    CleanAuthService,
    CleanTokenService,
)
from src.adapters.api.v1.auth.schemas import AuthResponse, LoginRequest, UserOut
from src.core.exceptions import AuthenticationError
from src.domain.interfaces.services import ITokenService, IUserAuthenticationService
from src.domain.value_objects.username import Username
from src.domain.value_objects.password import Password

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post(
    "/clean",
    response_model=AuthResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Authenticate user (Clean Architecture)",
    description="Clean architecture implementation of user authentication with enhanced security and domain events.",
)
async def clean_login_user(
    request: Request,
    payload: LoginRequest,
    auth_service: IUserAuthenticationService = Depends(CleanAuthService),
    token_service: ITokenService = Depends(CleanTokenService),
):
    """Authenticate user using clean architecture principles.

    This endpoint demonstrates clean architecture implementation with:
    - Domain-driven design with value objects
    - Proper separation of concerns
    - Domain events for audit trails
    - Enhanced security patterns
    - Comprehensive logging with correlation IDs

    Args:
        request (Request): FastAPI request object for security context
        payload (LoginRequest): User credentials
        auth_service (IUserAuthenticationService): Clean authentication service
        token_service (ITokenService): Clean token service

    Returns:
        AuthResponse: User details and JWT tokens

    Raises:
        HTTPException: Authentication failures with appropriate status codes

    Security Features:
        - Value object validation for usernames and passwords
        - Timing attack protection via constant-time operations
        - Comprehensive audit trails via domain events
        - Attack pattern detection
        - Secure logging with data masking
    """
    # Generate correlation ID for request tracking
    correlation_id = str(uuid.uuid4())
    
    # Extract security context
    client_ip = request.client.host or "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Create structured logger with correlation context
    request_logger = logger.bind(
        correlation_id=correlation_id,
        client_ip=client_ip[:15] + "***" if len(client_ip) > 15 else client_ip,
        user_agent=user_agent[:50] + "***" if len(user_agent) > 50 else user_agent,
        endpoint="clean_login",
    )
    
    request_logger.info(
        "Clean login attempt initiated",
        username_length=len(payload.username),
        has_password=bool(payload.password),
    )
    
    try:
        # Create domain value objects with validation
        username = Username(payload.username)
        password = Password(payload.password)
        
        request_logger.debug(
            "Domain value objects created",
            username_normalized=username.normalized_value[:3] + "***",
        )
        
        # Authenticate user using clean domain service
        user = await auth_service.authenticate_user(
            username=username,
            password=password,
            client_ip=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id,
        )
        
        request_logger.info(
            "User authenticated successfully",
            user_id=user.id,
            username=user.username[:3] + "***" if user.username else "Unknown",
        )
        
        # Create token pair using clean token service
        tokens = await token_service.create_token_pair(user)
        
        request_logger.info(
            "Authentication tokens created",
            user_id=user.id,
            token_type=tokens.get("token_type", "bearer"),
            expires_in=tokens.get("expires_in", 900),
        )
        
        # Return clean response
        return AuthResponse(
            tokens=tokens,
            user=UserOut.from_entity(user)
        )
        
    except ValueError as e:
        # Handle value object validation errors
        request_logger.warning(
            "Authentication failed - invalid input format",
            error=str(e),
            error_type="validation_error",
        )
        raise AuthenticationError(
            message="Invalid credentials format",
            language="en"  # TODO: Extract from request headers
        )
        
    except AuthenticationError as e:
        # Handle domain authentication errors
        request_logger.warning(
            "Authentication failed - domain error",
            error=str(e),
            error_type="authentication_error",
        )
        raise  # Re-raise to maintain proper HTTP status codes
        
    except Exception as e:
        # Handle unexpected errors
        request_logger.error(
            "Authentication failed - unexpected error",
            error=str(e),
            error_type=type(e).__name__,
        )
        raise AuthenticationError(
            message="Authentication service temporarily unavailable",
            language="en"
        )


# Alternative endpoint with explicit dependency injection for testing
@router.post(
    "/clean-explicit",
    response_model=AuthResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth", "testing"],
    summary="Authenticate user (Clean Architecture - Explicit DI)",
    description="Clean architecture login with explicit dependency injection for testing and demonstration.",
    include_in_schema=False,  # Hide from public API docs
)
async def clean_login_explicit_di(
    request: Request,
    payload: LoginRequest,
    auth_service: IUserAuthenticationService,
    token_service: ITokenService,
):
    """Clean login with explicit dependency injection.
    
    This endpoint variant accepts services directly without FastAPI dependency
    injection, making it easier to test and demonstrate clean architecture
    principles in isolation.
    
    This pattern is useful for:
    - Unit testing with mock services
    - Integration testing with specific implementations
    - Demonstrating dependency inversion principle
    - Manual service composition
    """
    return await clean_login_user(
        request=request,
        payload=payload,
        auth_service=auth_service,    
        token_service=token_service,
    ) 