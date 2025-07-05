import pytest
from fastapi import status
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_resend_confirmation_validation_error(async_client: AsyncClient):
    response = await async_client.post("/api/v1/auth/resend-confirmation", json={})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
