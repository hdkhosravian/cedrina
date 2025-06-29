"""Reset Password endpoint module following Domain-Driven Design principles.

This module handles password reset execution using valid tokens with clean architecture
principles. The API layer is kept thin with no business logic - all password reset
logic is delegated to domain services.

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

from src.adapters.api.v1.auth.schemas import MessageResponse, ResetPasswordRequest
from src.core.exceptions import (
    AuthenticationError,
    ForgotPasswordError,
    PasswordResetError,
    UserNotFoundError,
)
from src.core.ratelimiter import get_limiter
from src.domain.services.password_reset.password_reset_service import PasswordResetService
from src.infrastructure.dependency_injection.auth_dependencies import (
    get_password_reset_service,
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
    summary="Reset password with token",
    description=(
        "Executes a password reset using a valid token received via email. "
        "This endpoint follows clean architecture with no business logic in the API layer. "
        "All password reset logic is handled by domain services with proper value objects, "
        "domain events, and security context capture."
    ),
    responses={
        200: {"description": "Password successfully reset"},
        400: {"description": "Invalid or expired token"},
        422: {"description": "Validation error - weak password or invalid token format"},
        429: {"description": "Rate limit exceeded - too many reset attempts"},
        500: {"description": "Internal server error - password reset service unavailable"},
    },
)
@limiter.limit("5/hour")
async def reset_password(
    request: Request,
    payload: ResetPasswordRequest,
    password_reset_service: PasswordResetService = Depends(get_password_reset_service),
) -> MessageResponse:
    """Reset password using clean architecture and Domain-Driven Design principles.

    This endpoint implements a thin API layer that follows Domain-Driven Design
    and clean architecture principles:
    
    1. **No Business Logic**: All password reset logic is delegated to domain services
    2. **Security Context**: Captures client IP, user agent, and correlation ID
    3. **Domain Service Delegation**: Uses clean password reset execution service
    4. **Clean Error Handling**: Proper handling of domain exceptions
    5. **Secure Logging**: Implements data masking and correlation tracking
    6. **I18N Support**: All messages are internationalized
    7. **Token Validation**: Comprehensive token security and one-time use
    
    Password Reset Execution Flow:
    1. Extract security context from request (IP, User-Agent)
    2. Generate correlation ID for request tracing
    3. Delegate password reset execution to domain service
    4. Handle token validation and password policy errors appropriately
    5. Return success response after password update

    Args:
        request (Request): FastAPI request object for security context extraction
        payload (ResetPasswordRequest): Token and new password for reset
        password_reset_service (PasswordResetService): Domain password reset service

    Returns:
        MessageResponse: Success message confirming password reset

    Raises:
        HTTPException: Token validation failures or password policy violations

    Security Features:
        - Rate limiting to prevent abuse (5 requests per hour)
        - Token validation with timing attack protection
        - One-time use token enforcement
        - Password strength validation via domain value objects
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
        client_ip=client_ip[:15] + "***" if len(client_ip) > 15 else client_ip,
        user_agent=user_agent[:50] + "***" if len(user_agent) > 50 else user_agent,
        endpoint="reset_password",
        operation="password_reset_execution"
    )
    
    # Log password reset execution initiation
    request_logger.info(
        "Password reset execution initiated",
        token_prefix=payload.token[:8] + "***" if len(payload.token) > 8 else "***",
        has_new_password=bool(payload.new_password),
        security_context_captured=True
    )
    
    try:
        # Delegate all business logic to domain service
        # The domain service handles:
        # - Token format validation using value objects
        # - User lookup by token
        # - Token expiration and validity checks
        # - Password strength validation using value objects
        # - Password update and token invalidation
        # - Domain event publishing
        # - Comprehensive audit logging
        result = await password_reset_service.reset_password(
            token=payload.token,
            new_password=payload.new_password,
            language=language,
            user_agent=user_agent,
            ip_address=client_ip,
            correlation_id=correlation_id,
        )
        
        request_logger.info(
            "Password reset execution completed successfully by domain service",
            token_prefix=payload.token[:8] + "***" if len(payload.token) > 8 else "***"
        )

        # Return success message from domain service
        success_message = result.get("message", get_translated_message("password_reset_success", language))
        return MessageResponse(message=success_message)

    except PasswordResetError as e:
        # Handle password reset specific errors (invalid/expired token)
        request_logger.warning(
            "Password reset execution failed - token error",
            error_type="password_reset_error",
            error_message=str(e),
            token_prefix=payload.token[:8] + "***" if len(payload.token) > 8 else "***"
        )
        # Re-raise to maintain proper HTTP status codes and error context
        raise
        
    except UserNotFoundError as e:
        # Handle user not found errors
        request_logger.warning(
            "Password reset execution failed - user not found",
            error_type="user_not_found_error",
            error_message=str(e),
            token_prefix=payload.token[:8] + "***" if len(payload.token) > 8 else "***"
        )
        # Re-raise to maintain proper HTTP status codes and error context
        raise
        
    except (ForgotPasswordError, AuthenticationError) as e:
        # Handle domain errors - these are already properly logged by the domain service
        request_logger.warning(
            "Password reset execution failed - domain error",
            error_type=type(e).__name__,
            error_message=str(e),
            token_prefix=payload.token[:8] + "***" if len(payload.token) > 8 else "***"
        )
        # Re-raise to maintain proper HTTP status codes and error context
        raise
        
    except ValueError as e:
        # Handle password validation errors from value objects
        request_logger.warning(
            "Password reset execution failed - password validation error",
            error_type="password_validation_error",
            error_message=str(e),
            token_prefix=payload.token[:8] + "***" if len(payload.token) > 8 else "***"
        )
        # Convert to domain exception to maintain consistency
        raise PasswordResetError(
            get_translated_message("password_too_weak", language)
        ) from e
        
    except Exception as e:
        # Handle unexpected errors
        # These should not occur in normal operation and indicate system issues
        request_logger.error(
            "Password reset execution failed - unexpected error",
            error_type=type(e).__name__,
            error_message=str(e),
            token_prefix=payload.token[:8] + "***" if len(payload.token) > 8 else "***"
        )
        # Return generic error to prevent information leakage
        error_message = get_translated_message("password_reset_failed", language)
        raise ForgotPasswordError(error_message) from e 