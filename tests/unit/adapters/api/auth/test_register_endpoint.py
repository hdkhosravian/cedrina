import httpx
import pytest
from fastapi import status


@pytest.mark.asyncio
async def test_register_successful(async_client: httpx.AsyncClient, db_session):
    """Test successful user registration."""
    from unittest.mock import AsyncMock

    from src.adapters.api.v1.auth.dependencies import get_token_service, get_user_auth_service
    from src.domain.entities.user import Role, User
    from src.domain.services.auth.token import TokenService
    from src.domain.services.auth.user_authentication import UserAuthenticationService

    # Create mock user that should be returned by register_user
    mock_user = User(
        id=1,
        username="newuser123",
        email="newuser@example.com",
        hashed_password="hashed_password_123",
        role=Role.USER,
        is_active=True,
    )

    # Mock services
    mock_user_service = AsyncMock(spec=UserAuthenticationService)
    mock_user_service.register_user.return_value = mock_user

    mock_token_service = AsyncMock(spec=TokenService)
    mock_token_service.create_access_token.return_value = "mock_access_token"
    mock_token_service.create_refresh_token.return_value = "mock_refresh_token"

    # Override dependencies
    from src.main import app

    app.dependency_overrides[get_user_auth_service] = lambda: mock_user_service
    app.dependency_overrides[get_token_service] = lambda: mock_token_service

    try:
        response = await async_client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "TestPassword123!",
                "username": "newuser123",  # Fixed: use 'username' instead of 'full_name'
            },
        )

        # Fixed: successful registration should return HTTP 201, not 422
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        assert "user" in response_data
        assert "tokens" in response_data
        assert response_data["user"]["email"] == "newuser@example.com"
        assert response_data["user"]["username"] == "newuser123"
    finally:
        # Clean up dependency overrides
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_register_duplicate_email(async_client: httpx.AsyncClient, db_session):
    """Test registration with an existing email returns 409 conflict or 422."""
    from unittest.mock import AsyncMock

    from src.adapters.api.v1.auth.dependencies import get_user_auth_service
    from src.core.exceptions import DuplicateUserError
    from src.domain.services.auth.user_authentication import UserAuthenticationService

    # Mock service to raise DuplicateUserError for duplicate email
    mock_user_service = AsyncMock(spec=UserAuthenticationService)
    mock_user_service.register_user.side_effect = DuplicateUserError("Email already registered")

    # Override dependencies
    from src.main import app

    app.dependency_overrides[get_user_auth_service] = lambda: mock_user_service

    try:
        response = await async_client.post(
            "/api/v1/auth/register",
            json={
                "email": "existing@example.com",
                "password": "TestPassword123!",
                "username": "duplicateuser",  # Fixed: use 'username' instead of 'full_name'
            },
        )

        assert response.status_code == status.HTTP_409_CONFLICT
        assert "detail" in response.json()
    finally:
        # Clean up dependency overrides
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_register_weak_password(async_client: httpx.AsyncClient, db_session):
    """Test registration with weak password returns 422."""
    from unittest.mock import AsyncMock

    from src.adapters.api.v1.auth.dependencies import get_user_auth_service
    from src.core.exceptions import PasswordPolicyError
    from src.domain.services.auth.user_authentication import UserAuthenticationService

    # Mock service to raise PasswordPolicyError for weak password
    mock_user_service = AsyncMock(spec=UserAuthenticationService)
    mock_user_service.register_user.side_effect = PasswordPolicyError(
        "Password does not meet security requirements"
    )

    # Override dependencies
    from src.main import app

    app.dependency_overrides[get_user_auth_service] = lambda: mock_user_service

    try:
        response = await async_client.post(
            "/api/v1/auth/register",
            json={
                "email": "weakpass@example.com",
                "password": "weak",
                "username": "weakpassuser",  # Fixed: use 'username' instead of 'full_name'
            },
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert "detail" in response.json()
    finally:
        # Clean up dependency overrides
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_register_invalid_email(async_client: httpx.AsyncClient, db_session):
    """Test registration with invalid email format returns 422."""
    from unittest.mock import AsyncMock

    from src.adapters.api.v1.auth.dependencies import get_user_auth_service
    from src.domain.services.auth.user_authentication import UserAuthenticationService

    # Mock service to raise ValidationError for invalid email
    mock_user_service = AsyncMock(spec=UserAuthenticationService)
    mock_user_service.register_user.side_effect = ValueError("Invalid email format")

    # Override dependencies
    from src.main import app

    app.dependency_overrides[get_user_auth_service] = lambda: mock_user_service

    try:
        response = await async_client.post(
            "/api/v1/auth/register",
            json={
                "email": "invalid-email",
                "password": "TestPassword123!",
                "username": "invalidemailuser",  # Fixed: use 'username' instead of 'full_name'
            },
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert "detail" in response.json()
    finally:
        # Clean up dependency overrides
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_register_missing_fields(async_client: httpx.AsyncClient, db_session):
    """Test registration with missing fields returns 422."""
    # This test doesn't need mocking since it tests validation at the API level
    # before reaching the service layer
    response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "missing@example.com"
            # password and username are missing
        },
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json()
