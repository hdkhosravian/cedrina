"""HTTP endpoint for confirming user email addresses."""

from fastapi import APIRouter, Depends, Query, Request, status

from src.infrastructure.dependency_injection.auth_dependencies import (
    CleanEmailConfirmationService,
)
from src.adapters.api.v1.auth.schemas import MessageResponse
from src.core.exceptions import AuthenticationError, UserNotFoundError
from src.utils.i18n import get_request_language, get_translated_message

router = APIRouter()


@router.get("", response_model=MessageResponse, status_code=status.HTTP_200_OK)
async def confirm_email(
    request: Request,
    token: str = Query(...),
    service=Depends(CleanEmailConfirmationService),
):
    """Validate the token and activate the user's account."""

    language = get_request_language(request)
    try:
        await service.confirm_email(token, language)
        return MessageResponse(
            message=get_translated_message("email_confirmed_success", language)
        )
    except (AuthenticationError, UserNotFoundError) as e:
        raise e
