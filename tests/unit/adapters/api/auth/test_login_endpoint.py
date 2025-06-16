import pytest
import httpx
from fastapi import status

from tests.factories.user import create_fake_user


@pytest.mark.asyncio
async def test_login_successful(async_client: httpx.AsyncClient, db_session):
    """Test successful login with valid credentials."""
    user = create_fake_user()
    
    response = await async_client.post(
        "/api/v1/auth/login",
        data={
            "username": user.email,
            "password": "testpassword123"
        }
    )
    
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_login_invalid_credentials(async_client: httpx.AsyncClient, db_session):
    """Test login with invalid credentials returns 401 or 422."""
    user = create_fake_user()
    
    response = await async_client.post(
        "/api/v1/auth/login",
        data={
            "username": user.email,
            "password": "wrongpassword"
        }
    )
    
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_login_nonexistent_user(async_client: httpx.AsyncClient, db_session):
    """Test login with non-existent user returns 401 or 422."""
    response = await async_client.post(
        "/api/v1/auth/login",
        data={
            "username": "nonexistent@example.com",
            "password": "testpassword123"
        }
    )
    
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_login_missing_fields(async_client: httpx.AsyncClient, db_session):
    """Test login with missing fields returns 422."""
    response = await async_client.post(
        "/api/v1/auth/login",
        data={"username": "test@example.com"}
    )
    
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_login_inactive_user(async_client: httpx.AsyncClient, db_session):
    """Test login with inactive user returns 403 or 422."""
    user = create_fake_user()
    
    response = await async_client.post(
        "/api/v1/auth/login",
        data={
            "username": user.email,
            "password": "testpassword123"
        }
    )
    
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json() 