from unittest.mock import AsyncMock, MagicMock
import pytest
from fastapi.testclient import TestClient

from src.main import app
from src.domain.entities.user import User, Role
from src.core.exceptions import AuthenticationError
from src.adapters.api.v1.auth.dependencies import get_token_service
from src.core.dependencies.auth import get_current_user
from src.infrastructure.database.async_db import get_async_db
from src.infrastructure.redis import get_redis


@pytest.fixture
def mock_db_session():
    """Create a properly mocked async database session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.add = MagicMock()
    session.get = AsyncMock()
    session.exec = AsyncMock()
    return session


@pytest.fixture
def mock_redis_client():
    """Create a mocked Redis client."""
    redis = AsyncMock()
    redis.get = AsyncMock()
    redis.setex = AsyncMock()
    redis.delete = AsyncMock()
    return redis


@pytest.fixture
def mock_session_service():
    """Create a mocked session service."""
    service = AsyncMock()
    service.create_session = AsyncMock()
    service.revoke_session = AsyncMock()
    service.get_session = AsyncMock()
    service.revoke_token = AsyncMock()
    return service


@pytest.fixture
def test_user():
    """Create a test user for mocking purposes."""
    return User(
        id=1, 
        username="test", 
        email="test@example.com", 
        role=Role.USER, 
        is_active=True,
        hashed_password="$2b$12$test_hash"
    )


@pytest.fixture
def test_client_with_mocks(test_user, mock_db_session, mock_redis_client, mock_session_service):
    """Create a test client with dependency overrides."""
    
    # Create comprehensive token service mock
    token_service_mock = AsyncMock()
    token_service_mock.session_service = mock_session_service
    token_service_mock.validate_token.return_value = {"jti": "test_jti", "sub": str(test_user.id)}
    token_service_mock.revoke_access_token = AsyncMock()
    token_service_mock.revoke_refresh_token = AsyncMock()
    
    # Override dependencies using FastAPI's dependency_overrides
    app.dependency_overrides[get_async_db] = lambda: mock_db_session
    app.dependency_overrides[get_redis] = lambda: mock_redis_client
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[get_token_service] = lambda: token_service_mock
    
    # Create client
    client = TestClient(app)
    
    yield client, token_service_mock
    
    # Clean up overrides after test
    app.dependency_overrides.clear()


def test_logout_revokes_tokens_step_by_step(test_client_with_mocks):
    """Test successful logout flow."""
    client, token_service_mock = test_client_with_mocks

    # Test logout directly without registration/login
    logout_response = client.request(
        "DELETE",
        "/api/v1/auth/logout",
        json={"refresh_token": "test_refresh_token"},
        headers={"Authorization": "Bearer test_access_token"},
    )

    assert logout_response.status_code == 200
    assert logout_response.json()["message"] == "Logged out successfully"
    
    # Verify token service methods were called
    token_service_mock.validate_token.assert_called_once_with("test_access_token", "en")
    token_service_mock.revoke_access_token.assert_called_once_with("test_jti")
    token_service_mock.revoke_refresh_token.assert_called_once_with("test_refresh_token")


def test_logout_invalid_refresh_token(test_client_with_mocks):
    """Test logout with invalid refresh token returns 401."""
    client, token_service_mock = test_client_with_mocks
    
    # Configure mock to raise error on invalid refresh token
    token_service_mock.revoke_refresh_token.side_effect = AuthenticationError("Invalid refresh token")

    logout_response = client.request(
        "DELETE",
        "/api/v1/auth/logout",
        json={"refresh_token": "invalid_refresh_token"},
        headers={"Authorization": "Bearer test_access_token"},
    )

    assert logout_response.status_code == 401
    assert "Invalid refresh token" in logout_response.json()["detail"]


def test_logout_missing_authorization_header():
    """Test logout without authorization header returns 401."""
    # For this test, we need a clean client without mocks to test auth failure
    client = TestClient(app)

    logout_response = client.request(
        "DELETE",
        "/api/v1/auth/logout",
        json={"refresh_token": "test_refresh_token"},
        # No Authorization header
    )

    assert logout_response.status_code == 401
    assert logout_response.json()["detail"] == "Not authenticated"


def test_logout_invalid_access_token(test_client_with_mocks):
    """Test logout with invalid access token returns 401."""
    client, token_service_mock = test_client_with_mocks
    
    # Configure mock to raise error on invalid access token
    token_service_mock.validate_token.side_effect = AuthenticationError("Invalid token")

    logout_response = client.request(
        "DELETE",
        "/api/v1/auth/logout",
        json={"refresh_token": "test_refresh_token"},
        headers={"Authorization": "Bearer invalid_access_token"},
    )

    assert logout_response.status_code == 401
    assert "Invalid token" in logout_response.json()["detail"]


def test_logout_payload_validation_error(test_client_with_mocks):
    """Test logout without refresh_token in payload returns 422."""
    client, token_service_mock = test_client_with_mocks

    logout_response = client.request(
        "DELETE",
        "/api/v1/auth/logout",
        json={},  # Missing refresh_token
        headers={"Authorization": "Bearer test_access_token"},
    )

    assert logout_response.status_code == 422
    # Check that validation error mentions refresh_token field
    detail = logout_response.json()["detail"]
    assert any("refresh_token" in str(error) for error in detail)


def test_logout_successful_token_blacklisting(test_client_with_mocks):
    """Test that logout properly blacklists the access token."""
    client, token_service_mock = test_client_with_mocks

    logout_response = client.request(
        "DELETE",
        "/api/v1/auth/logout",
        json={"refresh_token": "test_refresh_token"},
        headers={"Authorization": "Bearer test_access_token"},
    )

    assert logout_response.status_code == 200
    
    # Verify both tokens were revoked
    token_service_mock.revoke_access_token.assert_called_once_with("test_jti")
    token_service_mock.revoke_refresh_token.assert_called_once_with("test_refresh_token")


def test_logout_with_session_service_error(test_client_with_mocks):
    """Test logout behavior when session service fails."""
    client, token_service_mock = test_client_with_mocks
    
    # Make session service fail
    token_service_mock.revoke_refresh_token.side_effect = AuthenticationError("Session already revoked")

    logout_response = client.request(
        "DELETE",
        "/api/v1/auth/logout",
        json={"refresh_token": "test_refresh_token"},
        headers={"Authorization": "Bearer test_access_token"},
    )

    assert logout_response.status_code == 401
    assert "Session already revoked" in logout_response.json()["detail"]


def test_logout_with_user_dependency_failure(test_user, mock_db_session, mock_redis_client, mock_session_service):
    """Test logout when current user dependency fails."""
    
    # Create comprehensive token service mock  
    token_service_mock = AsyncMock()
    token_service_mock.session_service = mock_session_service
    token_service_mock.validate_token.return_value = {"jti": "test_jti", "sub": str(test_user.id)}
    token_service_mock.revoke_access_token = AsyncMock()
    token_service_mock.revoke_refresh_token = AsyncMock()
    
    # Override dependencies but make get_current_user fail
    def failing_get_current_user():
        raise AuthenticationError("User not found")
    
    app.dependency_overrides[get_async_db] = lambda: mock_db_session
    app.dependency_overrides[get_redis] = lambda: mock_redis_client
    app.dependency_overrides[get_current_user] = failing_get_current_user
    app.dependency_overrides[get_token_service] = lambda: token_service_mock
    
    client = TestClient(app)
    
    try:
        logout_response = client.request(
            "DELETE",
            "/api/v1/auth/logout",
            json={"refresh_token": "test_refresh_token"},
            headers={"Authorization": "Bearer test_access_token"},
        )

        assert logout_response.status_code == 401
        assert "User not found" in logout_response.json()["detail"]
    finally:
        # Clean up overrides
        app.dependency_overrides.clear()
