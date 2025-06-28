from __future__ import annotations

"""/auth/change-password route module.

This module handles password changes for authenticated users in the Cedrina
authentication system. It provides a secure endpoint for users to change their
passwords with proper validation and security measures.
"""

from fastapi import APIRouter, Depends, status, Request

from src.adapters.api.v1.auth.schemas import ChangePasswordRequest, MessageResponse
from src.adapters.api.v1.auth.dependencies import get_user_auth_service
from src.core.dependencies.auth import get_current_user
from src.domain.entities.user import User
from src.domain.services.auth.user_authentication import UserAuthenticationService
from src.core.exceptions import AuthenticationError, PasswordPolicyError, PasswordValidationError
from src.utils.i18n import get_translated_message

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
    user_service: UserAuthenticationService = Depends(get_user_auth_service),
) -> MessageResponse:
    """
    Change the password for the currently authenticated user.

    This endpoint implements a secure password change process that:
    1. Validates the user is authenticated and active
    2. Verifies the old password is correct
    3. Ensures the new password meets security policy requirements
    4. Securely hashes and stores the new password
    5. Logs the password change for audit purposes

    Args:
        request (Request): FastAPI request object for language context.
        payload (ChangePasswordRequest): Request payload with old and new passwords.
        current_user (User): The authenticated user from token validation.
        user_service (UserAuthenticationService): Service for password operations.

    Returns:
        MessageResponse: Success message confirming password change.

    Raises:
        HTTPException: If authentication fails (401), validation fails (422),
            or password policy requirements are not met (400).

    Security:
        - Requires valid JWT token for authentication
        - Validates old password before allowing change
        - Enforces password policy to prevent weak passwords
        - Prevents password reuse by checking if new password differs from old
        - Uses bcrypt with configured work factor for secure hashing
        - Logs password change events for security audit
        - Rate limiting should be applied at the API layer to prevent abuse

    Rate Limiting:
        - This endpoint should be rate-limited to prevent brute force attacks
        - Recommended: 5 attempts per hour per user
        - Rate limiting is enforced by slowapi middleware
    """
    try:
        # Get the language from request state, fallback to 'en' if not set
        language = getattr(request.state, 'language', 'en')
        
        # Change the password using the user service
        await user_service.change_password(
            user_id=current_user.id,
            old_password=payload.old_password,
            new_password=payload.new_password
        )
        
        # Return success message
        success_message = get_translated_message("password_changed_successfully", language)
        return MessageResponse(message=success_message)
        
    except (AuthenticationError, PasswordPolicyError, PasswordValidationError) as e:
        # Re-raise authentication, policy, and password validation errors to be handled by FastAPI exception handlers
        raise
    except Exception as e:
        # Log unexpected errors for debugging while maintaining security
        language = getattr(request.state, 'language', 'en')
        error_message = get_translated_message("password_change_failed", language)
        from src.core.exceptions import DatabaseError
        raise DatabaseError(error_message) from e 