from __future__ import annotations

"""/auth/logout route module."""

from fastapi import APIRouter, Depends, status
from fastapi.security import OAuth2PasswordBearer

from src.adapters.api.v1.auth.schemas import LogoutRequest, MessageResponse
from src.adapters.api.v1.auth.dependencies import get_token_service
from src.core.dependencies.auth import get_current_user
from src.domain.entities.user import User
from src.domain.services.auth.token import TokenService

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


@router.delete(
    "",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Logout current user",
)
async def logout_user(
    payload: LogoutRequest,
    token: str = Depends(oauth2_scheme),
    current_user: User = Depends(get_current_user),
    token_service: TokenService = Depends(get_token_service),
) -> MessageResponse:
    """Invalidate the user's tokens and end their session."""

    decoded = await token_service.validate_token(token)
    await token_service.revoke_access_token(decoded["jti"])
    await token_service.revoke_refresh_token(payload.refresh_token)

    return MessageResponse(message="Logged out successfully")
