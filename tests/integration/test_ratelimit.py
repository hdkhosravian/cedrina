import time

import pytest
from fastapi.testclient import TestClient

from src.core.config.settings import settings
from src.core.exceptions import AuthenticationError
from src.core.ratelimiter import get_limiter
from src.main import app


@pytest.fixture(scope="function")
def client(monkeypatch):
    """Test client fixture that uses an in-memory rate-limiting backend.
    This fixture now has a 'function' scope to match the 'monkeypatch' fixture.
    """
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RATE_LIMIT_AUTH", "3/second")
    monkeypatch.setattr(settings, "RATE_LIMIT_STORAGE_URL", "memory://")

    app.state.limiter = get_limiter()
    with TestClient(app) as c:
        yield c


@pytest.mark.integration
@pytest.mark.asyncio
async def test_login_endpoint_is_rate_limited(client, mocker):
    # Arrange
    url = "/api/v1/auth/login"
    login_credentials_1 = {"username": "user1", "password": "password123"}
    login_credentials_2 = {"username": "user2", "password": "password123"}

    # Mock the authentication service and override the app dependency
    mock_auth_service = mocker.AsyncMock()
    mock_auth_service.authenticate_by_credentials.side_effect = AuthenticationError(
        "Invalid credentials"
    )

    # Override the dependency in the app
    from src.adapters.api.v1.auth.dependencies import get_user_auth_service
    from src.main import app

    app.dependency_overrides[get_user_auth_service] = lambda: mock_auth_service

    # Act
    # First request with first username - should pass (no rate limit)
    response = client.post(url, json=login_credentials_1)
    assert response.status_code == 401  # Authentication failure

    # Second request with first username - should pass (no rate limit yet)
    response = client.post(url, json=login_credentials_1)
    assert response.status_code == 401  # Authentication failure

    # Third request with second username - should pass (different username)
    response = client.post(url, json=login_credentials_2)
    assert response.status_code == 401  # Authentication failure

    # Fourth request with first username - should be rate-limited
    response = client.post(url, json=login_credentials_1)
    assert response.status_code == 429
    assert "Rate limit exceeded" in response.text

    # Wait for the rate-limiting window to reset (1 second)
    time.sleep(1)

    # This request with first username should now succeed again
    response = client.post(url, json=login_credentials_1)
    assert response.status_code == 401

    # Cleanup: Remove dependency override
    app.dependency_overrides.clear()
