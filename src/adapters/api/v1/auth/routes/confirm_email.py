from fastapi import APIRouter, Depends, Query, Request, status

from src.infrastructure.dependency_injection.auth_dependencies import (
    CleanEmailConfirmationService,
)
from src.adapters.api.v1.auth.schemas.responses.user import UserOut
from src.core.exceptions import AuthenticationError
from src.utils.i18n import get_request_language

router = APIRouter()


@router.get("", response_model=UserOut, status_code=status.HTTP_200_OK)
async def confirm_email(
    request: Request,
    token: str = Query(...),
    service=Depends(CleanEmailConfirmationService),
):
    language = get_request_language(request)
    try:
        user = await service.confirm_email(token, language)
        return UserOut.from_entity(user)
    except AuthenticationError as e:
        raise e
