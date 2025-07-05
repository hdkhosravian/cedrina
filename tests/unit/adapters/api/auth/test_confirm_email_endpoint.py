import pytest
from fastapi import status
from httpx import AsyncClient
from src.core.exceptions import UserNotFoundError


@pytest.mark.asyncio
async def test_confirm_email_missing_token(async_client: AsyncClient):
    response = await async_client.get("/api/v1/auth/confirm-email")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.asyncio
async def test_confirm_email_success(
    async_client: AsyncClient,
    mock_email_confirmation_service,
):
    response = await async_client.get("/api/v1/auth/confirm-email?token=abc")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "message" in data
    mock_email_confirmation_service.confirm_email.assert_called_once_with(
        "abc", "en"
    )


@pytest.mark.asyncio
async def test_confirm_email_invalid_token(
    async_client: AsyncClient, mock_email_confirmation_service
):
    mock_email_confirmation_service.confirm_email.side_effect = UserNotFoundError("bad")

    response = await async_client.get("/api/v1/auth/confirm-email?token=bad")

    assert response.status_code == status.HTTP_404_NOT_FOUND
    mock_email_confirmation_service.confirm_email.assert_called_once_with("bad", "en")
