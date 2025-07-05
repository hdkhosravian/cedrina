import pytest
from fastapi import status
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_confirm_email_missing_token(async_client: AsyncClient):
    response = await async_client.get("/api/v1/auth/confirm-email")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
