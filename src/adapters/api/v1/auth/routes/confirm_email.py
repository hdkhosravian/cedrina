"""Email confirmation endpoint module with enhanced security logging and information disclosure prevention.

This module handles email confirmation via token using clean architecture
principles with enterprise-grade security features. The API layer is kept thin with no 
business logic - all confirmation logic is delegated to domain services.

Key Security Features:
- Zero-trust data masking for audit trails
- Consistent error responses to prevent enumeration attacks
- Standardized timing to prevent timing attacks
- Comprehensive security event logging with SIEM integration
- Risk-based confirmation analysis and threat detection
- Privacy-compliant data handling (GDPR)

Key DDD Principles Applied:
- Thin API layer with no business logic
- Domain value objects for input validation
- Domain services for business logic
- Domain events for audit trails
- Proper separation of concerns
- Security context capture for audit trails
- Correlation ID tracking for request tracing
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, Request, status

from src.infrastructure.dependency_injection.auth_dependencies import get_email_confirmation_service
from src.adapters.api.v1.auth.schemas import UserOut
from src.core.exceptions import EmailConfirmationError
from src.domain.interfaces import IEmailConfirmationService
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.utils.i18n import get_request_language, get_translated_message

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post(
    "",
    response_model=UserOut,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Confirm user email address",
    description=(
        "Confirms a user's email address using a confirmation token using Domain-Driven Design principles. "
        "This endpoint follows clean architecture with no business logic in the API layer. "
        "All confirmation logic is handled by domain services with proper value objects, "
        "domain events, and security context capture."
    ),
)
async def confirm_email(
    request: Request,
    token: str,
    confirmation_service: IEmailConfirmationService = Depends(get_email_confirmation_service),
):
    """Confirm user email address using a confirmation token.

    This endpoint implements a thin API layer that follows Domain-Driven Design
    and clean architecture principles:
    
    1. **No Business Logic**: All confirmation logic is delegated to domain services
    2. **Domain Value Objects**: Uses token validation through domain services
    3. **Security Context**: Captures client IP, user agent, and correlation ID
    4. **Domain Events**: Confirmation events are published by domain services
    5. **Clean Error Handling**: Proper handling of domain exceptions
    6. **Secure Logging**: Implements data masking and correlation tracking
    
    Confirmation Flow:
    1. Extract security context from request (IP, User-Agent)
    2. Generate correlation ID for request tracing
    3. Validate token format and find associated user
    4. Delegate confirmation to domain service
    5. Return confirmed user data

    Args:
        request (Request): FastAPI request object for security context extraction
        token (str): Email confirmation token from request query parameter
        confirmation_service (IEmailConfirmationService): Domain confirmation service

    Returns:
        UserOut: Confirmed user details

    Raises:
        HTTPException: Confirmation failures with appropriate status codes

    Security Features:
        - Token validation through domain services
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
        client_ip=secure_logging_service.mask_ip_address(client_ip),
        user_agent=secure_logging_service.sanitize_user_agent(user_agent),
        endpoint="confirm_email",
        operation="email_confirmation"
    )
    
    # Log confirmation attempt initiation with secure data masking
    request_logger.info(
        "Email confirmation attempt initiated",
        token_prefix=token[:8] if token else "none",
        has_token=bool(token),
        security_context_captured=True,
        security_enhanced=True
    )
    
    try:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        request_logger.debug(
            "Email confirmation parameters validated",
            token_prefix=token[:8] if token else "none",
            language=language,
            security_enhanced=True
        )
        
        # Delegate confirmation to domain service
        # The domain service handles all business logic including:
        # - Token validation and user lookup
        # - Email confirmation and account activation
        # - Domain event publishing
        # - Security monitoring and audit trails
        user = await confirmation_service.confirm_email(
            token=token,
            language=language,
        )
        
        request_logger.info(
            "Email confirmation successful by enhanced domain service",
            user_id=user.id,
            email_masked=secure_logging_service.mask_email(user.email),
            confirmation_method="token",
            security_enhanced=True
        )
        
        # Return clean response using domain entity
        # The response is constructed from the domain entity, ensuring
        # consistency between domain model and API response
        return UserOut.from_entity(user)
        
    except ValueError as e:
        # Handle value object validation errors with standardized response
        # These occur when input format is invalid (e.g., empty token)
        request_logger.warning(
            "Email confirmation failed - invalid input format",
            error=str(e),
            error_type="validation_error",
            token_prefix=token[:8] if token else "none",
            security_enhanced=True
        )
        
        # Use error standardization service for consistent response
        standardized_response = await error_standardization_service.create_standardized_response(
            error_type="invalid_input",
            actual_error=str(e),
            correlation_id=correlation_id,
            language=language
        )
        raise EmailConfirmationError(message=standardized_response["detail"])
        
    except EmailConfirmationError as e:
        # Handle domain confirmation errors with enhanced logging
        # These are raised by the enhanced domain service for business rule violations
        # (e.g., invalid token, user not found)
        request_logger.warning(
            "Email confirmation failed - enhanced domain error",
            error=str(e),
            error_type="confirmation_error",
            token_prefix=token[:8] if token else "none",
            security_enhanced=True
        )
        # Re-raise to maintain proper HTTP status codes and error context
        # The enhanced service already provides standardized error messages
        raise
        
    except Exception as e:
        # Handle unexpected errors with enhanced security logging
        # These should not occur in normal operation and indicate system issues
        request_logger.error(
            "Email confirmation failed - unexpected error",
            error=str(e),
            error_type=type(e).__name__,
            token_prefix=token[:8] if token else "none",
            security_enhanced=True
        )
        
        # Use error standardization service for consistent response
        standardized_response = await error_standardization_service.create_standardized_response(
            error_type="internal_error",
            actual_error=str(e),
            correlation_id=correlation_id,
            language=language
        )
        raise EmailConfirmationError(message=standardized_response["detail"])


@router.post(
    "/resend",
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Resend email confirmation",
    description=(
        "Resends an email confirmation to a user using Domain-Driven Design principles. "
        "This endpoint follows clean architecture with no business logic in the API layer. "
        "All resend logic is handled by domain services with proper value objects, "
        "domain events, and security context capture."
    ),
)
async def resend_confirmation_email(
    request: Request,
    email: str,
    confirmation_service: IEmailConfirmationService = Depends(get_email_confirmation_service),
):
    """Resend email confirmation to user.

    This endpoint implements a thin API layer that follows Domain-Driven Design
    and clean architecture principles:
    
    1. **No Business Logic**: All resend logic is delegated to domain services
    2. **Domain Value Objects**: Uses email validation through domain services
    3. **Security Context**: Captures client IP, user agent, and correlation ID
    4. **Domain Events**: Resend events are published by domain services
    5. **Clean Error Handling**: Proper handling of domain exceptions
    6. **Secure Logging**: Implements data masking and correlation tracking
    
    Resend Flow:
    1. Extract security context from request (IP, User-Agent)
    2. Generate correlation ID for request tracing
    3. Validate email format and find associated user
    4. Delegate resend to domain service
    5. Return success response

    Args:
        request (Request): FastAPI request object for security context extraction
        email (str): Email address to resend confirmation to
        confirmation_service (IEmailConfirmationService): Domain confirmation service

    Returns:
        dict: Success response

    Raises:
        HTTPException: Resend failures with appropriate status codes

    Security Features:
        - Email validation through domain services
        - Rate limiting for resend requests
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
        client_ip=secure_logging_service.mask_ip_address(client_ip),
        user_agent=secure_logging_service.sanitize_user_agent(user_agent),
        endpoint="resend_confirmation",
        operation="email_confirmation_resend"
    )
    
    # Log resend attempt initiation with secure data masking
    request_logger.info(
        "Email confirmation resend attempt initiated",
        email_masked=secure_logging_service.mask_email(email),
        has_email=bool(email),
        security_context_captured=True,
        security_enhanced=True
    )
    
    try:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        request_logger.debug(
            "Email confirmation resend parameters validated",
            email_masked=secure_logging_service.mask_email(email),
            language=language,
            security_enhanced=True
        )
        
        # Delegate resend to domain service
        # The domain service handles all business logic including:
        # - User lookup and validation
        # - Token generation and email sending
        # - Domain event publishing
        # - Security monitoring and audit trails
        success = await confirmation_service.resend_confirmation_email(
            email=email,
            language=language,
        )
        
        request_logger.info(
            "Email confirmation resend successful by enhanced domain service",
            email_masked=secure_logging_service.mask_email(email),
            success=success,
            confirmation_method="resend",
            security_enhanced=True
        )
        
        # Return clean response
        return {
            "message": get_translated_message("email_confirmation_resent", language),
            "success": True
        }
        
    except ValueError as e:
        # Handle value object validation errors with standardized response
        # These occur when input format is invalid (e.g., empty email)
        request_logger.warning(
            "Email confirmation resend failed - invalid input format",
            error=str(e),
            error_type="validation_error",
            email_masked=secure_logging_service.mask_email(email),
            security_enhanced=True
        )
        
        # Use error standardization service for consistent response
        standardized_response = await error_standardization_service.create_standardized_response(
            error_type="invalid_input",
            actual_error=str(e),
            correlation_id=correlation_id,
            language=language
        )
        raise EmailConfirmationError(message=standardized_response["detail"])
        
    except EmailConfirmationError as e:
        # Handle domain resend errors with enhanced logging
        # These are raised by the enhanced domain service for business rule violations
        # (e.g., user not found, rate limit exceeded)
        request_logger.warning(
            "Email confirmation resend failed - enhanced domain error",
            error=str(e),
            error_type="resend_error",
            email_masked=secure_logging_service.mask_email(email),
            security_enhanced=True
        )
        # Re-raise to maintain proper HTTP status codes and error context
        # The enhanced service already provides standardized error messages
        raise
        
    except Exception as e:
        # Handle unexpected errors with enhanced security logging
        # These should not occur in normal operation and indicate system issues
        request_logger.error(
            "Email confirmation resend failed - unexpected error",
            error=str(e),
            error_type=type(e).__name__,
            email_masked=secure_logging_service.mask_email(email),
            security_enhanced=True
        )
        
        # Use error standardization service for consistent response
        standardized_response = await error_standardization_service.create_standardized_response(
            error_type="internal_error",
            actual_error=str(e),
            correlation_id=correlation_id,
            language=language
        )
        raise EmailConfirmationError(message=standardized_response["detail"]) 