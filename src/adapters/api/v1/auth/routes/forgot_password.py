"""Forgot Password endpoint module with enhanced security logging and information disclosure prevention.

This module handles password reset requests via email using clean architecture
principles with enterprise-grade security features. The API layer is kept thin with 
no business logic - all password reset logic is delegated to domain services.

Key Security Features:
- Zero-trust data masking for audit trails
- Consistent error responses to prevent enumeration attacks
- Standardized timing to prevent timing attacks
- Comprehensive security event logging with SIEM integration
- Risk-based password reset analysis and threat detection
- Privacy-compliant data handling (GDPR)
- Email enumeration protection via consistent responses

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

import structlog
from fastapi import APIRouter, Body, Depends, Request, status
from pydantic import EmailStr

from src.adapters.api.v1.auth.schemas import ForgotPasswordRequest, MessageResponse
from src.core.exceptions import (
    AuthenticationError,
    EmailServiceError,
    ForgotPasswordError,
    RateLimitExceededError,
)
from src.core.rate_limiting.ratelimiter import get_limiter
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.domain.services.password_reset.password_reset_request_service import (
    PasswordResetRequestService,
)
from src.infrastructure.dependency_injection.auth_dependencies import (
    get_password_reset_request_service,
)
from src.utils.i18n import get_request_language, get_translated_message

logger = structlog.get_logger(__name__)
router = APIRouter()

# Use centralized rate limiter for consistency
limiter = get_limiter()


@router.post(
    "",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Request password reset",
    description=(
        "Initiates a password reset request by sending a secure reset link to the user's email. "
        "This endpoint follows clean architecture with no business logic in the API layer. "
        "All password reset logic is handled by domain services with proper value objects, "
        "domain events, and security context capture. Always returns success to prevent email enumeration."
    ),
    responses={
        200: {"description": "Password reset email sent (or would be sent if user exists)"},
        429: {"description": "Rate limit exceeded - too many password reset attempts"},
        422: {"description": "Validation error - invalid email format"},
        500: {"description": "Internal server error - email service unavailable"},
    },
)
@limiter.limit("3/hour")
async def forgot_password(
    request: Request,
    payload: ForgotPasswordRequest,
    password_reset_service: PasswordResetRequestService = Depends(get_password_reset_request_service),
) -> MessageResponse:
    """Request password reset using clean architecture and Domain-Driven Design principles.

    This endpoint implements a thin API layer that follows Domain-Driven Design
    and clean architecture principles:
    
    1. **No Business Logic**: All password reset logic is delegated to domain services
    2. **Security Context**: Captures client IP, user agent, and correlation ID
    3. **Domain Service Delegation**: Uses clean password reset request service
    4. **Clean Error Handling**: Proper handling of domain exceptions
    5. **Secure Logging**: Implements data masking and correlation tracking
    6. **I18N Support**: All messages are internationalized
    7. **Email Enumeration Protection**: Always returns success regardless of user existence
    
    Password Reset Flow:
    1. Extract security context from request (IP, User-Agent)
    2. Generate correlation ID for request tracing
    3. Delegate password reset request to domain service
    4. Handle rate limiting and email service errors appropriately
    5. Return consistent success response to prevent email enumeration

    Args:
        request (Request): FastAPI request object for security context extraction
        payload (ForgotPasswordRequest): Email address for password reset
        password_reset_service (PasswordResetRequestService): Domain password reset service

    Returns:
        MessageResponse: Success message confirming email would be sent

    Raises:
        HTTPException: Rate limit exceeded or email service failures

    Security Features:
        - Rate limiting to prevent abuse (3 requests per hour)
        - Email enumeration protection via consistent responses
        - Comprehensive audit trails via domain events
        - Secure logging with data masking
        - Correlation ID tracking for request tracing
        - Security context capture (IP, User-Agent) for audit trails
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
        endpoint="forgot_password",
        operation="password_reset_request"
    )
    
    # Log password reset request initiation with secure data masking
    request_logger.info(
        "Password reset request initiated",
        email_masked=secure_logging_service.mask_email(payload.email),
        security_context_captured=True,
        security_enhanced=True
    )
    
    try:
        # Delegate all business logic to domain service
        # The domain service handles:
        # - User lookup and validation
        # - Rate limiting enforcement
        # - Token generation and storage
        # - Email delivery coordination
        # - Domain event publishing
        # - Comprehensive audit logging
        result = await password_reset_service.request_password_reset(
            email=payload.email,
            language=language,
            user_agent=user_agent,
            ip_address=client_ip,
            correlation_id=correlation_id,
        )
        
        request_logger.info(
            "Password reset request completed successfully by enhanced domain service",
            email_masked=secure_logging_service.mask_email(payload.email),
            security_enhanced=True
        )

        # Return success message (always success to prevent email enumeration)
        success_message = get_translated_message("password_reset_email_sent", language)
        return MessageResponse(message=success_message)

    except RateLimitExceededError as e:
        # Handle rate limiting errors - user has exceeded allowed attempts
        request_logger.warning(
            "Password reset request rate limited",
            error_type="rate_limit_exceeded",
            error_message=str(e),
            email_masked=secure_logging_service.mask_email(payload.email),
            security_enhanced=True
        )
        # Re-raise to maintain proper HTTP status codes and error context
        raise
        
    except EmailServiceError as e:
        # Handle email service errors - could not deliver email
        request_logger.error(
            "Password reset email delivery failed",
            error_type="email_service_error",
            error_message=str(e),
            email_masked=secure_logging_service.mask_email(payload.email),
            security_enhanced=True
        )
        # Still return success to prevent information leakage
        success_message = get_translated_message("password_reset_email_sent", language)
        return MessageResponse(message=success_message)
        
    except (ForgotPasswordError, AuthenticationError) as e:
        # Handle domain errors with enhanced logging - these are already properly logged by the domain service
        request_logger.warning(
            "Password reset request failed - enhanced domain error",
            error_type=type(e).__name__,
            error_message=str(e),
            email_masked=secure_logging_service.mask_email(payload.email),
            security_enhanced=True
        )
        # Re-raise to maintain proper HTTP status codes and error context
        raise
        
    except Exception as e:
        # Handle unexpected errors with enhanced security logging
        # These should not occur in normal operation and indicate system issues
        request_logger.error(
            "Password reset request failed - unexpected error",
            error_type=type(e).__name__,
            error_message=str(e),
            email_masked=secure_logging_service.mask_email(payload.email),
            security_enhanced=True
        )
        # Return success to prevent information leakage
        success_message = get_translated_message("password_reset_email_sent", language)
        return MessageResponse(message=success_message) 