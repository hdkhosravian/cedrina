import datetime
from unittest.mock import AsyncMock

import jwt
import pytest
import pytest_asyncio
from fastapi import Depends
from fastapi.testclient import TestClient
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config.settings import settings
from src.core.dependencies.auth import get_current_admin_user, get_current_user
from src.core.rate_limiting.ratelimiter import get_limiter
from src.domain.entities.user import Role, User
from src.domain.services.auth.token import TokenService
from src.infrastructure.database import get_db
from src.infrastructure.redis import get_redis
from src.main import app as main_app  # Import with an alias to avoid conflicts


@pytest_asyncio.fixture
async def db_session():
    session = AsyncMock(spec=AsyncSession)
    return session


@pytest_asyncio.fixture
async def redis_client(mocker):
    return mocker.AsyncMock(spec=Redis)


@pytest.fixture
def user():
    return User(id=1, username="testuser", email="test@example.com", role=Role.USER, is_active=True)


@pytest.fixture
def admin_user():
    return User(id=2, username="admin", email="admin@example.com", role=Role.ADMIN, is_active=True)


@pytest.fixture
def app():
    """Provides the actual FastAPI app instance."""
    return main_app


@pytest.fixture
def client(app, db_session, redis_client):
    """Override get_db and get_redis dependencies, and provide a TestClient.
    This fixture now correctly uses the 'app' fixture.
    """
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_redis] = lambda: redis_client
    app.state.limiter = get_limiter()
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def token_service(mocker):
    mock = mocker.AsyncMock(spec=TokenService)
    # Create a properly formatted JWT token for testing
    payload = {
        "sub": "1",
        "jti": "mocked_jti",
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
    }
    token = jwt.encode(payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256")
    mock.create_access_token = mocker.AsyncMock(return_value=token)
    mock.validate_token = mocker.AsyncMock(return_value=payload)
    mock.is_token_blacklisted = mocker.AsyncMock(return_value=False)
    return mock


class TestGetCurrentUser:
    """Unit tests for authentication dependencies (get_current_user & get_current_admin_user)."""

    @pytest.mark.asyncio
    async def test_get_current_user_valid_token(
        self, app, client, db_session, user, token_service, mocker
    ):
        """Ensure that a valid JWT allows retrieval of the current user."""
        # Arrange
        token = await token_service.create_access_token(user)
        headers = {"Authorization": f"Bearer {token}"}
        db_session.get.return_value = user

        mocker.patch("src.core.dependencies.auth.TokenService", return_value=token_service)

        @app.get("/users/me")
        async def read_users_me(current_user: User = Depends(get_current_user)):
            return current_user

        # Act
        response = client.get("/users/me", headers=headers)

        # Assert
        assert response.status_code == 200
        assert response.json()["username"] == user.username

    @pytest.mark.asyncio
    async def test_get_current_user_invalid_token(self, app, client):
        """An invalid JWT should result in 401."""
        headers = {"Authorization": "Bearer invalidtoken"}

        @app.get("/users/me/invalid")
        async def read_users_me_invalid(current_user: User = Depends(get_current_user)):
            return current_user

        response = client.get("/users/me/invalid", headers=headers)

        assert response.status_code == 401
        assert "Invalid token" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_admin_route_permission_denied(
        self, app, client, db_session, user, token_service, mocker
    ):
        """Non-admin users must not access admin routes."""
        token = await token_service.create_access_token(user)
        headers = {"Authorization": f"Bearer {token}"}
        db_session.get.return_value = user

        mocker.patch("src.core.dependencies.auth.TokenService", return_value=token_service)

        @app.get("/admin/test")
        async def admin_route(current_user: User = Depends(get_current_admin_user)):
            return {"message": "Admin route"}

        response = client.get("/admin/test", headers=headers)

        assert response.status_code == 403 or response.status_code == 401

    @pytest.mark.asyncio
    async def test_admin_route_success(
        self, app, client, admin_user, token_service, db_session, mocker
    ):
        """Admin users should access admin endpoints successfully."""
        token = await token_service.create_access_token(admin_user)
        headers = {"Authorization": f"Bearer {token}"}
        db_session.get.return_value = admin_user

        mocker.patch("src.core.dependencies.auth.TokenService", return_value=token_service)

        @app.get("/admin/test/success")
        async def admin_route_success(current_user: User = Depends(get_current_admin_user)):
            return {"message": "Admin route"}

        response = client.get("/admin/test/success", headers=headers)

        assert response.status_code == 200
