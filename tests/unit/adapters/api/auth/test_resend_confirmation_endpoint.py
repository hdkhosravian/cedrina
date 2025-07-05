import pytest
from fastapi import status
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_resend_confirmation_validation_error(async_client: AsyncClient):
    response = await async_client.post("/api/v1/auth/resend-confirmation", json={})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.asyncio
async def test_resend_confirmation_success(
    async_client: AsyncClient, mock_email_confirmation_request_service
):
    payload = {"email": "test@example.com"}
    response = await async_client.post("/api/v1/auth/resend-confirmation", json=payload)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "message" in data
    mock_email_confirmation_request_service.resend_confirmation_email.assert_called_once_with(
        payload["email"], "en"
    )
