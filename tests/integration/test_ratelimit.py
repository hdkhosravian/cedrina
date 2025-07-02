import time

import pytest
from fastapi.testclient import TestClient

from src.core.config.settings import settings
from src.core.exceptions import AuthenticationError
from src.core.rate_limiting.ratelimiter import get_limiter
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
    # Use passwords that meet value object requirements but will fail authentication
    login_credentials_1 = {"username": "testuser1", "password": "TempPass123!"}
    login_credentials_2 = {"username": "testuser2", "password": "TempPass123!"}

    # Mock the authentication service and override the app dependency
    mock_auth_service = mocker.AsyncMock()
    mock_auth_service.authenticate_user.side_effect = AuthenticationError(
        "Invalid credentials"
    )

    # Override the dependency in the app
    from src.infrastructure.dependency_injection.auth_dependencies import CleanAuthService
    from src.main import app

    # Override the actual dependency that creates the service
    from src.infrastructure.dependency_injection.auth_dependencies import get_user_authentication_service
    app.dependency_overrides[get_user_authentication_service] = lambda user_repository=None, event_publisher=None: mock_auth_service

    # Act
    # Note: Since we switched to clean architecture with value objects,
    # invalid credentials that don't meet validation requirements will return 422.
    # For rate limiting tests, we need to use credentials that pass validation 
    # but fail authentication. For now, let's test the rate limiting on validation errors.
    
    # Use invalid credentials that will trigger validation errors (422)
    invalid_creds = {"username": "x", "password": "weak"}  # Too short username, weak password
    
    # First request - should get validation error (422)
    response = client.post(url, json=invalid_creds)
    assert response.status_code == 422  # Validation failure

    # Second request - should get validation error (422)
    response = client.post(url, json=invalid_creds)
    assert response.status_code == 422  # Validation failure

    # Third request with different invalid credentials
    response = client.post(url, json={"username": "y", "password": "bad"})
    assert response.status_code == 422  # Validation failure

    # Fourth request - should be rate-limited
    response = client.post(url, json=invalid_creds)
    assert response.status_code == 429
    assert "Rate limit exceeded" in response.text

    # Wait for the rate-limiting window to reset (1 second)
    time.sleep(1)

    # This request should now get validation error again (not rate limited)
    response = client.post(url, json=invalid_creds)
    assert response.status_code == 422

    # Cleanup: Remove dependency override
    app.dependency_overrides.clear()
