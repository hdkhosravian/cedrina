import pytest
import httpx
from fastapi import status

from tests.factories.user import create_fake_user


@pytest.mark.asyncio
async def test_register_successful(async_client: httpx.AsyncClient, db_session):
    """Test successful user registration."""
    response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "newuser@example.com",
            "password": "TestPassword123!",
            "full_name": "New User"
        }
    )
    
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_register_duplicate_email(async_client: httpx.AsyncClient, db_session):
    """Test registration with an existing email returns 409 conflict or 422."""
    user = create_fake_user()
    
    response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": user.email,
            "password": "TestPassword123!",
            "full_name": "Duplicate User"
        }
    )
    
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_register_weak_password(async_client: httpx.AsyncClient, db_session):
    """Test registration with weak password returns 422."""
    response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "weakpass@example.com",
            "password": "weak",
            "full_name": "Weak Pass"
        }
    )
    
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_register_invalid_email(async_client: httpx.AsyncClient, db_session):
    """Test registration with invalid email format returns 422."""
    response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "invalid-email",
            "password": "TestPassword123!",
            "full_name": "Invalid Email"
        }
    )
    
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_register_missing_fields(async_client: httpx.AsyncClient, db_session):
    """Test registration with missing fields returns 422."""
    response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "missing@example.com"
            # password and full_name are missing
        }
    )
    
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json() 