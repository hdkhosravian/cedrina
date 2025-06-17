import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from src.core.dependencies.auth import get_current_user, get_current_admin_user
from src.domain.entities.user import User, Role
from src.domain.services.auth.token import TokenService
from src.infrastructure.database import get_db
from src.infrastructure.redis import get_redis
from src.core.exceptions import PermissionError, AuthenticationError
from src.core.handlers import permission_error_handler


@pytest_asyncio.fixture
async def db_session():
    session = AsyncMock(spec=AsyncSession)
    return session


@pytest_asyncio.fixture
async def redis_client():
    return AsyncMock(spec=Redis)


@pytest.fixture
def user():
    return User(id=1, username="testuser", email="test@example.com", role=Role.USER, is_active=True)


@pytest.fixture
def admin_user():
    return User(id=2, username="admin", email="admin@example.com", role=Role.ADMIN, is_active=True)


@pytest.fixture
def app(db_session, redis_client, user, admin_user):
    """Create an ephemeral FastAPI app that mounts endpoints using the deps."""

    _app = FastAPI()
    _app.add_exception_handler(PermissionError, permission_error_handler)

    # Add a dummy middleware to set the language state for i18n
    @_app.middleware("http")
    async def set_language_middleware(request: Request, call_next):
        request.state.language = "en"  # Default to 'en' for these tests
        response = await call_next(request)
        return response

    # Patch dependencies inside this app context only
    _app.dependency_overrides[get_db] = lambda: db_session
    _app.dependency_overrides[get_redis] = lambda: redis_client

    # -- Secure endpoint (any user) -------------------------------------------
    @_app.get("/secure")
    async def secure_route(request: Request, current: User = Depends(get_current_user)):  # noqa: D401
        return {"user_id": current.id}

    # -- Admin endpoint --------------------------------------------------------
    @_app.get("/admin")
    async def admin_route(request: Request, current: User = Depends(get_current_admin_user)):  # noqa: D401
        return {"user_id": current.id}

    return _app


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.mark.asyncio
async def test_get_current_user_valid_token(client, db_session, redis_client, user):
    # Arrange
    token = "dummy-token"

    with patch.object(TokenService, "validate_token", AsyncMock(return_value={"sub": str(user.id)})):
        db_session.get.return_value = user

        # Act
        response = client.get("/secure", headers={"Authorization": f"Bearer {token}"})

    # Assert
    assert response.status_code == 200
    assert response.json() == {"user_id": user.id}


@pytest.mark.asyncio
async def test_get_current_user_invalid_token(client, db_session, redis_client):
    # Arrange
    token = "bad-token"

    with patch.object(TokenService, "validate_token", AsyncMock(side_effect=AuthenticationError("fail"))):
        # Act
        response = client.get("/secure", headers={"Authorization": f"Bearer {token}"})

    # Assert
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_admin_route_permission_denied(client, db_session, redis_client, user):
    token = "dummy-token"

    with patch.object(TokenService, "validate_token", AsyncMock(return_value={"sub": str(user.id)})):
        db_session.get.return_value = user

        response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403
    assert "The user does not have administrative privileges." in response.json()["detail"]


@pytest.mark.asyncio
async def test_admin_route_success(client, db_session, redis_client, admin_user):
    token = "dummy-token"

    with patch.object(TokenService, "validate_token", AsyncMock(return_value={"sub": str(admin_user.id)})):
        db_session.get.return_value = admin_user

        response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json() == {"user_id": admin_user.id} 