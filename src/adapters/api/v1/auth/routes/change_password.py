from __future__ import annotations

"""/auth/change-password route module with enhanced security logging and information disclosure prevention.

This module handles password changes for authenticated users in the Cedrina
authentication system with enterprise-grade security features. It provides a secure 
endpoint for users to change their passwords with proper validation and security measures.

Key Security Features:
- Zero-trust data masking for audit trails
- Consistent error responses to prevent enumeration attacks
- Standardized timing to prevent timing attacks
- Comprehensive security event logging with SIEM integration
- Risk-based password change analysis and threat detection
- Privacy-compliant data handling (GDPR)
- Password change security validation and monitoring
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, Request, status

from src.adapters.api.v1.auth.schemas import ChangePasswordRequest, MessageResponse
from src.core.dependencies.auth import get_current_user
from src.core.exceptions import AuthenticationError, PasswordPolicyError, PasswordValidationError
from src.domain.entities.user import User
from src.domain.interfaces.services import IPasswordChangeService
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.infrastructure.dependency_injection.auth_dependencies import (
    get_password_change_service,
)
from src.utils.i18n import get_request_language, get_translated_message

router = APIRouter()


@router.put(
    "",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Change user password",
    description="Changes the password for the currently authenticated user. Requires old password verification and new password validation.",
    responses={
        200: {"description": "Password successfully changed"},
        400: {"description": "Invalid request - password validation failed"},
        401: {"description": "Authentication failed - invalid old password or user not found"},
        422: {"description": "Validation error - password policy requirements not met"},
    },
)
async def change_password(
    request: Request,
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    password_change_service: IPasswordChangeService = Depends(get_password_change_service),
) -> MessageResponse:
    """Change password using clean architecture and Domain-Driven Design principles.

    This endpoint implements a thin API layer that follows clean architecture:
    
    1. **No Business Logic**: All password change logic is delegated to domain service
    2. **Security Context**: Captures client IP, user agent, and correlation ID
    3. **Domain Service Delegation**: Uses clean password change service
    4. **Clean Error Handling**: Proper handling of domain exceptions
    5. **Secure Logging**: Implements data masking and correlation tracking
    6. **I18N Support**: All messages are internationalized

    Args:
        request (Request): FastAPI request object for security context extraction
        payload (ChangePasswordRequest): Password change request data
        current_user (User): The authenticated user from token validation
        password_change_service (IPasswordChangeService): Clean domain service

    Returns:
        MessageResponse: Success message confirming password change

    Raises:
        HTTPException: Password change failures with appropriate status codes

    Security Features:
        - Domain value object validation for passwords
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
    
    # Extract language from request for I18N
    language = get_request_language(request)
    
    # Create structured logger with correlation context and security information
    logger = structlog.get_logger(__name__)
    request_logger = logger.bind(
        correlation_id=correlation_id,
        user_id=current_user.id,
        client_ip=secure_logging_service.mask_ip_address(client_ip),
        user_agent=secure_logging_service.sanitize_user_agent(user_agent),
        endpoint="change_password",
        operation="password_change"
    )
    
    # Log password change attempt initiation with secure data masking
    request_logger.info(
        "Password change attempt initiated",
        username_masked=secure_logging_service.mask_username(current_user.username),
        has_old_password=bool(payload.old_password),
        has_new_password=bool(payload.new_password),
        security_context_captured=True,
        security_enhanced=True
    )
    
    try:
        # Delegate all business logic to domain service
        # The domain service handles:
        # - Password validation using value objects
        # - Old password verification
        # - Password policy enforcement
        # - Password reuse prevention
        # - Domain event publishing
        # - Comprehensive audit logging
        await password_change_service.change_password(
            user_id=current_user.id,
            old_password=payload.old_password,
            new_password=payload.new_password,
            language=language,
            client_ip=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id,
        )
        
        request_logger.info(
            "Password change completed successfully by enhanced domain service",
            username_masked=secure_logging_service.mask_username(current_user.username),
            security_enhanced=True
        )

        # Return success message
        success_message = get_translated_message("password_changed_successfully", language)
        return MessageResponse(message=success_message)

    except (AuthenticationError, PasswordPolicyError, PasswordValidationError) as e:
        # Handle domain errors with enhanced logging - these are already properly logged by the domain service
        request_logger.warning(
            "Password change failed - enhanced domain error",
            error_type=type(e).__name__,
            error_message=str(e),
            username_masked=secure_logging_service.mask_username(current_user.username),
            security_enhanced=True
        )
        # Re-raise to maintain proper HTTP status codes and error context
        raise
        
    except Exception as e:
        # Handle unexpected errors with enhanced security logging
        # These should not occur in normal operation and indicate system issues
        request_logger.error(
            "Password change failed - unexpected error",
            error_type=type(e).__name__,
            error_message=str(e),
            username_masked=secure_logging_service.mask_username(current_user.username),
            security_enhanced=True
        )
        
        # Use error standardization service for consistent response
        standardized_response = await error_standardization_service.create_standardized_response(
            error_type="internal_error",
            actual_error=str(e),
            correlation_id=correlation_id,
            language=language
        )
        raise AuthenticationError(message=standardized_response["detail"]) from e
