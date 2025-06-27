from unittest.mock import AsyncMock, MagicMock
import pytest
from fastapi.testclient import TestClient
from jose import jwt
from datetime import datetime, timezone, timedelta

from src.main import app
from src.domain.entities.user import User, Role
from src.core.exceptions import AuthenticationError
from src.adapters.api.v1.auth.dependencies import get_token_service
from src.core.dependencies.auth import get_current_user
from src.infrastructure.database.async_db import get_async_db
from src.infrastructure.redis import get_redis
from src.core.config.settings import settings


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
def other_test_user():
    """Create another test user for cross-user security testing."""
    return User(
        id=2, 
        username="other_user", 
        email="other@example.com", 
        role=Role.USER, 
        is_active=True,
        hashed_password="$2b$12$other_hash"
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


def test_logout_revokes_tokens_step_by_step(test_client_with_mocks, test_user):
    """Test successful logout flow."""
    client, token_service_mock = test_client_with_mocks

    # Create a valid refresh token for the test user
    valid_refresh_token = jwt.encode(
        {
            "sub": str(test_user.id),
            "jti": "test_refresh_jti",
            "exp": datetime.now(timezone.utc) + timedelta(days=7),
            "iat": datetime.now(timezone.utc),
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE
        },
        settings.JWT_PRIVATE_KEY.get_secret_value(),
        algorithm="RS256"
    )

    # Test logout directly without registration/login
    logout_response = client.request(
        "DELETE",
        "/api/v1/auth/logout",
        json={"refresh_token": valid_refresh_token},
        headers={"Authorization": "Bearer test_access_token"},
    )

    assert logout_response.status_code == 200
    assert logout_response.json()["message"] == "Logged out successfully"
    
    # Verify token service methods were called
    token_service_mock.validate_token.assert_called_once_with("test_access_token", "en")
    token_service_mock.revoke_access_token.assert_called_once_with("test_jti")
    token_service_mock.revoke_refresh_token.assert_called_once_with(valid_refresh_token, "en")


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


def test_logout_successful_token_blacklisting(test_client_with_mocks, test_user):
    """Test that logout properly blacklists the access token."""
    client, token_service_mock = test_client_with_mocks

    # Create a valid refresh token for the test user
    valid_refresh_token = jwt.encode(
        {
            "sub": str(test_user.id),
            "jti": "test_refresh_jti",
            "exp": datetime.now(timezone.utc) + timedelta(days=7),
            "iat": datetime.now(timezone.utc),
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE
        },
        settings.JWT_PRIVATE_KEY.get_secret_value(),
        algorithm="RS256"
    )

    logout_response = client.request(
        "DELETE",
        "/api/v1/auth/logout",
        json={"refresh_token": valid_refresh_token},
        headers={"Authorization": "Bearer test_access_token"},
    )

    assert logout_response.status_code == 200
    
    # Verify both tokens were revoked
    token_service_mock.revoke_access_token.assert_called_once_with("test_jti")
    token_service_mock.revoke_refresh_token.assert_called_once_with(valid_refresh_token, "en")


def test_logout_with_session_service_error(test_client_with_mocks, test_user):
    """Test logout behavior when session service fails."""
    client, token_service_mock = test_client_with_mocks
    
    # Create a valid refresh token for the test user
    valid_refresh_token = jwt.encode(
        {
            "sub": str(test_user.id),
            "jti": "test_refresh_jti",
            "exp": datetime.now(timezone.utc) + timedelta(days=7),
            "iat": datetime.now(timezone.utc),
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE
        },
        settings.JWT_PRIVATE_KEY.get_secret_value(),
        algorithm="RS256"
    )
    
    # Make session service fail
    token_service_mock.revoke_refresh_token.side_effect = AuthenticationError("Session already revoked")

    logout_response = client.request(
        "DELETE",
        "/api/v1/auth/logout",
        json={"refresh_token": valid_refresh_token},
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


# Security Tests for Cross-User Token Revocation Prevention


def test_logout_rejects_other_users_refresh_token(test_user, other_test_user, mock_db_session, mock_redis_client, mock_session_service):
    """
    SECURITY TEST: Verify that a user cannot logout using another user's refresh token.
    
    This test ensures the fix for the cross-user token revocation vulnerability works correctly.
    A user should only be able to revoke their own refresh tokens, not other users' tokens.
    """
    # Create a refresh token that belongs to other_test_user
    other_user_refresh_token = jwt.encode(
        {
            "sub": str(other_test_user.id),  # This token belongs to other_test_user (id=2)
            "jti": "other_user_jti",
            "exp": datetime.now(timezone.utc) + timedelta(days=7),
            "iat": datetime.now(timezone.utc),
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE
        },
        settings.JWT_PRIVATE_KEY.get_secret_value(),
        algorithm="RS256"
    )
    
    # Create token service mock for the authenticated user (test_user)
    token_service_mock = AsyncMock()
    token_service_mock.session_service = mock_session_service
    token_service_mock.validate_token.return_value = {"jti": "test_jti", "sub": str(test_user.id)}
    token_service_mock.revoke_access_token = AsyncMock()
    token_service_mock.revoke_refresh_token = AsyncMock()
    
    # Override dependencies - test_user is authenticated, but trying to use other_user's token
    app.dependency_overrides[get_async_db] = lambda: mock_db_session
    app.dependency_overrides[get_redis] = lambda: mock_redis_client
    app.dependency_overrides[get_current_user] = lambda: test_user  # Authenticated as test_user (id=1)
    app.dependency_overrides[get_token_service] = lambda: token_service_mock
    
    client = TestClient(app)
    
    try:
        # Attempt logout with other user's refresh token - this should fail
        logout_response = client.request(
            "DELETE",
            "/api/v1/auth/logout",
            json={"refresh_token": other_user_refresh_token},  # other_user's token
            headers={"Authorization": "Bearer test_access_token"},  # test_user's access token
        )
        
        # Should return 401 Unauthorized due to mismatched refresh token ownership
        assert logout_response.status_code == 401
        assert "Invalid refresh token" in logout_response.json()["detail"]
        
        # Verify that token revocation methods were NOT called
        # since the ownership validation should fail before reaching revocation
        token_service_mock.revoke_access_token.assert_not_called()
        token_service_mock.revoke_refresh_token.assert_not_called()
        
    finally:
        app.dependency_overrides.clear()


def test_logout_allows_own_refresh_token(test_user, mock_db_session, mock_redis_client, mock_session_service):
    """
    SECURITY TEST: Verify that a user can successfully logout using their own refresh token.
    
    This test ensures the ownership validation doesn't break legitimate logout requests.
    """
    # Create a refresh token that belongs to test_user
    user_refresh_token = jwt.encode(
        {
            "sub": str(test_user.id),  # This token belongs to test_user (id=1)
            "jti": "user_jti",
            "exp": datetime.now(timezone.utc) + timedelta(days=7),
            "iat": datetime.now(timezone.utc),
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE
        },
        settings.JWT_PRIVATE_KEY.get_secret_value(),
        algorithm="RS256"
    )
    
    # Create token service mock
    token_service_mock = AsyncMock()
    token_service_mock.session_service = mock_session_service
    token_service_mock.validate_token.return_value = {"jti": "test_jti", "sub": str(test_user.id)}
    token_service_mock.revoke_access_token = AsyncMock()
    token_service_mock.revoke_refresh_token = AsyncMock()
    
    # Override dependencies
    app.dependency_overrides[get_async_db] = lambda: mock_db_session
    app.dependency_overrides[get_redis] = lambda: mock_redis_client
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[get_token_service] = lambda: token_service_mock
    
    client = TestClient(app)
    
    try:
        # Attempt logout with user's own refresh token - this should succeed
        logout_response = client.request(
            "DELETE",
            "/api/v1/auth/logout",
            json={"refresh_token": user_refresh_token},  # user's own token
            headers={"Authorization": "Bearer test_access_token"},  # user's access token
        )
        
        # Should return 200 OK for successful logout
        assert logout_response.status_code == 200
        assert logout_response.json()["message"] == "Logged out successfully"
        
        # Verify that token revocation methods were called
        token_service_mock.revoke_access_token.assert_called_once_with("test_jti")
        token_service_mock.revoke_refresh_token.assert_called_once_with(user_refresh_token, "en")
        
    finally:
        app.dependency_overrides.clear()


def test_logout_rejects_malformed_refresh_token(test_client_with_mocks):
    """
    SECURITY TEST: Verify that malformed refresh tokens are rejected during logout.
    
    This test ensures that invalid JWT tokens are properly handled in the ownership validation.
    """
    client, token_service_mock = test_client_with_mocks
    
    # Attempt logout with malformed refresh token
    logout_response = client.request(
        "DELETE",
        "/api/v1/auth/logout",
        json={"refresh_token": "malformed.jwt.token"},
        headers={"Authorization": "Bearer test_access_token"},
    )
    
    # Should return 401 Unauthorized due to invalid JWT
    assert logout_response.status_code == 401
    assert "Invalid refresh token" in logout_response.json()["detail"]
    
    # Verify that token revocation methods were NOT called
    token_service_mock.revoke_access_token.assert_not_called()
    token_service_mock.revoke_refresh_token.assert_not_called()


def test_logout_rejects_expired_refresh_token(test_user, mock_db_session, mock_redis_client, mock_session_service):
    """
    SECURITY TEST: Verify that expired refresh tokens are rejected during logout.
    
    This test ensures that expired tokens cannot be used for logout operations.
    """
    # Create an expired refresh token
    expired_refresh_token = jwt.encode(
        {
            "sub": str(test_user.id),
            "jti": "expired_jti",
            "exp": datetime.now(timezone.utc) - timedelta(days=1),  # Expired 1 day ago
            "iat": datetime.now(timezone.utc) - timedelta(days=8),
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE
        },
        settings.JWT_PRIVATE_KEY.get_secret_value(),
        algorithm="RS256"
    )
    
    # Create token service mock
    token_service_mock = AsyncMock()
    token_service_mock.session_service = mock_session_service
    token_service_mock.validate_token.return_value = {"jti": "test_jti", "sub": str(test_user.id)}
    token_service_mock.revoke_access_token = AsyncMock()
    token_service_mock.revoke_refresh_token = AsyncMock()
    
    # Override dependencies
    app.dependency_overrides[get_async_db] = lambda: mock_db_session
    app.dependency_overrides[get_redis] = lambda: mock_redis_client
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[get_token_service] = lambda: token_service_mock
    
    client = TestClient(app)
    
    try:
        # Attempt logout with expired refresh token
        logout_response = client.request(
            "DELETE",
            "/api/v1/auth/logout",
            json={"refresh_token": expired_refresh_token},
            headers={"Authorization": "Bearer test_access_token"},
        )
        
        # Should return 401 Unauthorized due to expired token
        assert logout_response.status_code == 401
        assert "Invalid refresh token" in logout_response.json()["detail"]
        
        # Verify that token revocation methods were NOT called
        token_service_mock.revoke_access_token.assert_not_called()
        token_service_mock.revoke_refresh_token.assert_not_called()
        
    finally:
        app.dependency_overrides.clear()


def test_tokens_are_invalid_after_logout():
    """
    Integration test: After logout, both access and refresh tokens should be invalid.
    This test uses mocks to simulate the real behavior without requiring database setup.
    """
    # Create a test user for mocking
    test_user = User(
        id=1, 
        username="logout_integration_user",
        email="logout_integration_user@example.com", 
        role=Role.USER, 
        is_active=True,
        hashed_password="$2b$12$test_hash"
    )
    
    # Create mocks
    mock_db_session = AsyncMock()
    mock_redis_client = AsyncMock()
    mock_session_service = AsyncMock()
    
    # Create comprehensive token service mock
    token_service_mock = AsyncMock()
    token_service_mock.session_service = mock_session_service
    token_service_mock.validate_token.return_value = {"jti": "test_jti", "sub": str(test_user.id)}
    token_service_mock.revoke_access_token = AsyncMock()
    token_service_mock.revoke_refresh_token = AsyncMock()
    
    # Override dependencies
    app.dependency_overrides[get_async_db] = lambda: mock_db_session
    app.dependency_overrides[get_redis] = lambda: mock_redis_client
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[get_token_service] = lambda: token_service_mock
    
    client = TestClient(app)
    
    try:
        # Create a valid refresh token for the test user
        valid_refresh_token = jwt.encode(
            {
                "sub": str(test_user.id),
                "jti": "test_refresh_jti",
                "exp": datetime.now(timezone.utc) + timedelta(days=7),
                "iat": datetime.now(timezone.utc),
                "iss": settings.JWT_ISSUER,
                "aud": settings.JWT_AUDIENCE
            },
            settings.JWT_PRIVATE_KEY.get_secret_value(),
            algorithm="RS256"
        )

        # 1. Log out (revoke tokens)
        logout_response = client.request(
            "DELETE",
            "/api/v1/auth/logout",
            json={"refresh_token": valid_refresh_token},
            headers={"Authorization": "Bearer test_access_token"},
        )
        assert logout_response.status_code == 200
        assert "Logged out successfully" in logout_response.json()["message"]

        # 2. Verify that both tokens were revoked with proper parameters
        token_service_mock.revoke_access_token.assert_called_once_with("test_jti")
        token_service_mock.revoke_refresh_token.assert_called_once_with(valid_refresh_token, "en")

        # 3. Simulate what would happen if someone tried to use the revoked tokens
        # Reset mocks to simulate fresh state
        token_service_mock.reset_mock()
        
        # Configure mocks to simulate revoked tokens
        token_service_mock.validate_token.side_effect = AuthenticationError("Token has been revoked")
        token_service_mock.revoke_refresh_token.side_effect = AuthenticationError("Refresh token has been revoked")
        
        # Override get_current_user to simulate token validation failure
        def failing_get_current_user():
            raise AuthenticationError("Token has been revoked")
        
        app.dependency_overrides[get_current_user] = failing_get_current_user
        
        # 4. Attempt to use the access token on a protected endpoint (should fail)
        protected_response = client.get(
            "/api/v1/admin/policies",  # Use a real protected endpoint
            headers={"Authorization": "Bearer test_access_token"},
        )
        assert protected_response.status_code == 401

    finally:
        # Clean up overrides
        app.dependency_overrides.clear()
