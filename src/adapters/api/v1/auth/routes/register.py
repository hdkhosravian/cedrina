from __future__ import annotations

"""/auth/register route module.

This module handles the registration of new users in the Cedrina authentication
system using clean architecture principles and Domain-Driven Design.
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, Request, status

from src.infrastructure.dependency_injection.auth_dependencies import (
    CleanRegistrationService,
    CleanTokenService,
)
from src.adapters.api.v1.auth.schemas import AuthResponse, RegisterRequest, UserOut
from src.core.exceptions import AuthenticationError
from src.domain.interfaces.services import ITokenService, IUserRegistrationService
from src.domain.value_objects.email import Email
from src.domain.value_objects.password import Password
from src.domain.value_objects.username import Username
from src.utils.i18n import get_request_language, get_translated_message

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post(
    "",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["auth"],
    summary="Register a new user",
    description="Creates a new user account with username, email, and password using clean architecture principles.",
)
async def register_user(
    request: Request,
    payload: RegisterRequest,
    registration_service: IUserRegistrationService = Depends(CleanRegistrationService),
    token_service: ITokenService = Depends(CleanTokenService),
):
    """Register a new user with the provided credentials using clean architecture.

    This endpoint creates a user account using clean architecture principles:
    - Domain value objects for input validation
    - Domain services for business logic
    - Domain events for audit trails
    - Proper separation of concerns
    - Enhanced security patterns

    Args:
        request (Request): FastAPI request object for security context
        payload (RegisterRequest): User registration data
        registration_service (IUserRegistrationService): Clean registration service
        token_service (ITokenService): Clean token service

    Returns:
        AuthResponse: User details and JWT tokens

    Raises:
        HTTPException: Registration failures with appropriate status codes

    Security Features:
        - Value object validation for usernames, emails, and passwords
        - Comprehensive audit trails via domain events
        - Attack pattern detection
        - Secure logging with data masking
        - Rate limiting via middleware (slowapi)
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
        endpoint="register",
    )
    
    request_logger.info(
        "Registration attempt initiated",
        username_length=len(payload.username),
        email_length=len(payload.email),
        has_password=bool(payload.password),
    )
    
    try:
        # Create domain value objects with validation
        username = Username.create_safe(payload.username)
        email = Email.create_normalized(payload.email)
        password = Password(payload.password)
        
        # Extract language from request for I18N
        language = get_request_language(request)
        
        request_logger.debug(
            "Domain value objects created",
            username_normalized=username.value[:3] + "***",
            email_normalized=email.value[:3] + "***",
        )
        
        # Register user using clean domain service
        user = await registration_service.register_user(
            username=username,
            email=email,
            password=password,
            language=language,
            client_ip=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id,
        )
        
        request_logger.info(
            "User registered successfully",
            user_id=user.id,
            username=user.username[:3] + "***" if user.username else "Unknown",
            email=user.email[:3] + "***" if user.email else "Unknown",
        )
        
        # Create token pair using clean token service
        # Use the adapter's create_token_pair method for convenience
        if hasattr(token_service, 'create_token_pair'):
            tokens = await token_service.create_token_pair(user)
        else:
            # Fallback to individual token creation
            access_token = await token_service.create_access_token(user)
            refresh_token = await token_service.create_refresh_token(user)
            tokens = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": 900,
            }
        
        request_logger.info(
            "Registration tokens created",
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
            "Registration failed - invalid input format",
            error=str(e),
            error_type="validation_error",
        )
        raise AuthenticationError(
            message=get_translated_message("invalid_registration_data_format", language)
        )
        
    except AuthenticationError as e:
        # Handle domain registration errors
        request_logger.warning(
            "Registration failed - domain error",
            error=str(e),
            error_type="registration_error",
        )
        raise  # Re-raise to maintain proper HTTP status codes
        
    except Exception as e:
        # Handle unexpected errors
        request_logger.error(
            "Registration failed - unexpected error",
            error=str(e),
            error_type=type(e).__name__,
        )
        raise AuthenticationError(
            message=get_translated_message("registration_service_unavailable", language)
        )
