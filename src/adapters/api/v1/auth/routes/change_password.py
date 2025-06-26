from __future__ import annotations

"""/auth/change-password route module."""

from fastapi import APIRouter, Depends, status, Request

from src.adapters.api.v1.auth.schemas import ChangePasswordRequest, MessageResponse
from src.adapters.api.v1.auth.dependencies import get_user_auth_service
from src.core.dependencies.auth import get_current_user
from src.utils.i18n import get_translated_message
from src.domain.entities.user import User
from src.domain.services.auth.user_authentication import UserAuthenticationService

router = APIRouter()


@router.post(
    "",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Change user password",
    description="Allows an authenticated user to change their password.",
)
async def change_password(
    request: Request,
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    user_service: UserAuthenticationService = Depends(get_user_auth_service),
):
    """Handle ``POST /auth/change-password`` for authenticated users.

    The endpoint verifies the supplied ``current_password`` against the
    authenticated user's credentials and, if valid, updates the password after
    enforcing the configured password policy. A success message is returned in
    the user's preferred language. If the provided current password is wrong an
    :class:`IncorrectPasswordError` is raised with a ``400`` response. New
    password policy violations raise :class:`PasswordPolicyError` (``422``) so
    the session remains active.
    """
    await user_service.change_password(
        current_user.id,
        payload.current_password,
        payload.new_password,
    )
    message = get_translated_message("password_changed", request.state.language)
    return MessageResponse(message=message)
