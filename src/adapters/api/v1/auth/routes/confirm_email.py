"""Email confirmation route module with enhanced security logging.

This module handles email confirmation operations in the Cedrina authentication
system using clean architecture principles and Domain-Driven Design.
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from src.infrastructure.dependency_injection.auth_dependencies import (
    CleanEmailConfirmationService,
)
from src.adapters.api.v1.auth.schemas import UserOut
from src.core.exceptions import AuthenticationError
from src.domain.interfaces import IEmailConfirmationService
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.utils.i18n import get_request_language

logger = structlog.get_logger(__name__)
router = APIRouter()


class ConfirmEmailRequest(BaseModel):
    """Request model for email confirmation."""
    token: str


class ConfirmEmailResponse(BaseModel):
    """Response model for email confirmation."""
    message: str
    user: UserOut


class ResendConfirmationRequest(BaseModel):
    """Request model for resending email confirmation."""
    email: str


class ResendConfirmationResponse(BaseModel):
    """Response model for resending email confirmation."""
    message: str


@router.post(
    "/confirm",
    response_model=ConfirmEmailResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Confirm email address",
    description="Confirms a user's email address using a confirmation token.",
)
async def confirm_email(
    request: Request,
    payload: ConfirmEmailRequest,
    email_confirmation_service: IEmailConfirmationService = Depends(CleanEmailConfirmationService),
):
    """Confirm user email address with token.

    Args:
        request: FastAPI request object for security context
        payload: Email confirmation data
        email_confirmation_service: Email confirmation service

    Returns:
        ConfirmEmailResponse: Success message and user details

    Raises:
        HTTPException: Confirmation failures with appropriate status codes
    """
    # Generate correlation ID for request tracking
    correlation_id = str(uuid.uuid4())
    
    # Extract security context
    client_ip = request.client.host or "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Create structured logger
    request_logger = logger.bind(
        correlation_id=correlation_id,
        client_ip=secure_logging_service.mask_ip_address(client_ip),
        user_agent=secure_logging_service.sanitize_user_agent(user_agent),
        endpoint="confirm_email",
        operation="email_confirmation"
    )
    
    request_logger.info(
        "Email confirmation attempt initiated",
        token_length=len(payload.token),
        security_enhanced=True
    )
    
    try:
        # Extract language from request
        language = get_request_language(request)
        
        # Confirm email using domain service
        user = await email_confirmation_service.confirm_email(
            payload.token,
            correlation_id,
        )
        
        request_logger.info(
            "Email confirmed successfully",
            user_id=user.id,
            email_masked=secure_logging_service.mask_email(user.email),
            security_enhanced=True
        )
        
        return ConfirmEmailResponse(
            message="Email confirmed successfully",
            user=UserOut.from_entity(user)
        )
        
    except AuthenticationError as e:
        request_logger.warning(
            "Email confirmation failed",
            error=str(e),
            error_type="authentication_error",
            token_length=len(payload.token),
            security_enhanced=True
        )
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
        
    except Exception as e:
        request_logger.error(
            "Email confirmation failed - unexpected error",
            error=str(e),
            error_type=type(e).__name__,
            token_length=len(payload.token),
            security_enhanced=True
        )
        
        # Use error standardization service for consistent response
        language = get_request_language(request)
        standardized_response = await error_standardization_service.create_standardized_response(
            error_type="internal_error",
            actual_error=str(e),
            correlation_id=correlation_id,
            language=language
        )
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=standardized_response["detail"]
        )


@router.post(
    "/resend",
    response_model=ResendConfirmationResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Resend email confirmation",
    description="Resends email confirmation to a user's email address.",
)
async def resend_confirmation(
    request: Request,
    payload: ResendConfirmationRequest,
    email_confirmation_service: IEmailConfirmationService = Depends(CleanEmailConfirmationService),
):
    """Resend email confirmation to user.

    Args:
        request: FastAPI request object for security context
        payload: Resend confirmation data
        email_confirmation_service: Email confirmation service

    Returns:
        ResendConfirmationResponse: Success message

    Raises:
        HTTPException: Resend failures with appropriate status codes
    """
    # Generate correlation ID for request tracking
    correlation_id = str(uuid.uuid4())
    
    # Extract security context
    client_ip = request.client.host or "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Create structured logger
    request_logger = logger.bind(
        correlation_id=correlation_id,
        client_ip=secure_logging_service.mask_ip_address(client_ip),
        user_agent=secure_logging_service.sanitize_user_agent(user_agent),
        endpoint="resend_confirmation",
        operation="email_confirmation_resend"
    )
    
    request_logger.info(
        "Resend email confirmation attempt initiated",
        email_masked=secure_logging_service.mask_email(payload.email),
        security_enhanced=True
    )
    
    try:
        # Extract language from request
        language = get_request_language(request)
        
        # Resend confirmation using domain service
        success = await email_confirmation_service.resend_confirmation_email(
            payload.email,
            language,
            correlation_id,
        )
        
        request_logger.info(
            "Email confirmation resent",
            email_masked=secure_logging_service.mask_email(payload.email),
            success=success,
            security_enhanced=True
        )
        
        return ResendConfirmationResponse(
            message="If the email address is registered, you will receive a confirmation email shortly"
        )
        
    except AuthenticationError as e:
        request_logger.warning(
            "Email confirmation resend failed",
            error=str(e),
            error_type="authentication_error",
            email_masked=secure_logging_service.mask_email(payload.email),
            security_enhanced=True
        )
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
        
    except Exception as e:
        request_logger.error(
            "Email confirmation resend failed - unexpected error",
            error=str(e),
            error_type=type(e).__name__,
            email_masked=secure_logging_service.mask_email(payload.email),
            security_enhanced=True
        )
        
        # Use error standardization service for consistent response
        language = get_request_language(request)
        standardized_response = await error_standardization_service.create_standardized_response(
            error_type="internal_error",
            actual_error=str(e),
            correlation_id=correlation_id,
            language=language
        )
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=standardized_response["detail"]
        )