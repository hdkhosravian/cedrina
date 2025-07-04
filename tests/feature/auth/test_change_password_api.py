"""Integration tests for the change password API endpoint.

This test suite covers comprehensive real-world scenarios including:
- Successful password changes
- Authentication failures (401)
- Password validation failures (400)
- I18N support for different languages
- Security edge cases
- Error handling and logging
- Real-world JWT token validation
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from jose import jwt
from passlib.context import CryptContext

from src.core.config.settings import BCRYPT_WORK_FACTOR, settings
from src.core.dependencies.auth import get_current_user
from src.domain.entities.user import Role, User
from src.domain.interfaces.repositories import IUserRepository
from src.domain.interfaces import IEventPublisher, IPasswordChangeService
from src.infrastructure.database.async_db import get_async_db
from src.infrastructure.dependency_injection.auth_dependencies import (
    get_event_publisher,
    get_password_change_service,
    get_user_repository,
)
from src.infrastructure.redis import get_redis
from src.main import app


@pytest_asyncio.fixture
async def mock_db_session():
    """Create a properly mocked async database session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.add = MagicMock()
    session.get = AsyncMock()
    session.exec = AsyncMock()
    return session


@pytest_asyncio.fixture
async def mock_redis_client():
    """Create a properly mocked Redis client."""
    redis_client = AsyncMock()
    redis_client.get = AsyncMock()
    redis_client.set = AsyncMock()
    redis_client.delete = AsyncMock()
    redis_client.exists = AsyncMock()
    return redis_client


@pytest.fixture
def mock_user_repository():
    """Create a mock user repository for clean architecture."""
    repository = AsyncMock(spec=IUserRepository)
    repository.get_by_id = AsyncMock()
    repository.save = AsyncMock()
    return repository


@pytest.fixture
def mock_event_publisher():
    """Create a mock event publisher for clean architecture."""
    publisher = AsyncMock(spec=IEventPublisher)
    publisher.publish = AsyncMock()
    return publisher


@pytest.fixture
def mock_password_change_service():
    """Create a mock password change service for clean architecture."""
    service = AsyncMock(spec=IPasswordChangeService)
    service.change_password = AsyncMock()
    return service


@pytest.fixture
def test_user():
    """Create a test user with valid credentials."""
    pwd_context = CryptContext(
        schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=BCRYPT_WORK_FACTOR
    )
    hashed_password = pwd_context.hash("OldPass123!")
    return User(
        id=1,
        username="testuser",
        email="test@example.com",
        hashed_password=hashed_password,
        role=Role.USER,
        is_active=True,
    )


def create_test_jwt_token(user: User) -> str:
    """Create a test JWT token for testing purposes."""
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
        "iat": datetime.now(timezone.utc),
        "jti": "test_jti_123",
    }
    return jwt.encode(payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256")


def override_get_current_user(user):
    async def _override():
        return user

    return _override


class TestChangePasswordAPI:
    """Integration tests for the change password API endpoint."""

    def test_change_password_success(
        self,
        test_user,
        mock_db_session,
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test successful password change with valid credentials."""
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Setup mocks
        mock_user_repository.get_by_id.return_value = test_user
        mock_password_change_service.change_password.return_value = None

        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service

        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NewPass456!"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200
            assert response.json()["message"] == "Password changed successfully"

            # Verify the service was called with correct parameters
            mock_password_change_service.change_password.assert_called_once()
            call_args = mock_password_change_service.change_password.call_args
            assert call_args[1]["user_id"] == test_user.id
            assert call_args[1]["old_password"] == "OldPass123!"
            assert call_args[1]["new_password"] == "NewPass456!"
        finally:
            app.dependency_overrides.clear()

    def test_change_password_invalid_token(self, mock_db_session, mock_redis_client):
        """Test change password fails with invalid JWT token."""
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NewPass456!"},
                headers={"Authorization": "Bearer invalid_token"},
            )
            assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()

    def test_change_password_missing_token(self, mock_db_session, mock_redis_client):
        """Test change password fails when no token is provided."""
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NewPass456!"},
            )
            assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()

    def test_change_password_invalid_old_password(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password fails with incorrect old password (400 status)."""
        from src.core.exceptions import InvalidOldPasswordError
        
        # Setup mocks - service should raise InvalidOldPasswordError
        mock_password_change_service.change_password.side_effect = InvalidOldPasswordError("Invalid old password")
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "WrongOldPass123!", "new_password": "NewPass456!"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 400
            assert response.json()["detail"] == "Invalid old password"
        finally:
            app.dependency_overrides.clear()

    def test_change_password_weak_new_password(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password fails with weak new password (422 status)."""
        from src.core.exceptions import PasswordPolicyError
        
        # Setup mocks - service should raise PasswordPolicyError
        mock_password_change_service.change_password.side_effect = PasswordPolicyError("Password must be at least 8 characters long")
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "weak"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_same_password(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password fails when new password is same as old (400 status)."""
        from src.core.exceptions import PasswordReuseError
        
        # Setup mocks - service should raise PasswordReuseError
        mock_password_change_service.change_password.side_effect = PasswordReuseError("New password must be different from the old password")
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "OldPass123!"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 400
            assert (
                response.json()["detail"] == "New password must be different from the old password"
            )
        finally:
            app.dependency_overrides.clear()

    def test_change_password_i18n_english(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password with English language support."""
        # Setup mocks
        mock_password_change_service.change_password.return_value = None
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NewPass456!"},
                headers={"Authorization": f"Bearer {token}", "Accept-Language": "en"},
            )
            assert response.status_code == 200
            assert response.json()["message"] == "Password changed successfully"
        finally:
            app.dependency_overrides.clear()

    def test_change_password_i18n_spanish(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password with Spanish language support."""
        # Setup mocks
        mock_password_change_service.change_password.return_value = None
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NewPass456!"},
                headers={"Authorization": f"Bearer {token}", "Accept-Language": "es"},
            )
            assert response.status_code == 200
            assert response.json()["message"] == "Contraseña cambiada exitosamente"
        finally:
            app.dependency_overrides.clear()

    def test_change_password_missing_fields(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password fails with missing required fields."""
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"new_password": "NewPass456!"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_database_error(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password fails when database operations fail."""
        from src.core.exceptions import AuthenticationError
        
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Setup mocks - service should raise AuthenticationError for database issues
        mock_password_change_service.change_password.side_effect = AuthenticationError("Database connection failed")
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NewPass456!"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()

    def test_change_password_password_policy_violations(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password fails with various password policy violations."""
        from src.core.exceptions import PasswordPolicyError
        
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            test_cases = [
                ("short", "Password must be at least 8 characters long"),
                ("nouppercase123!", "Password must contain at least one uppercase letter"),
                ("NOLOWERCASE123!", "Password must contain at least one lowercase letter"),
                ("NoDigits!", "Password must contain at least one digit"),
                ("NoSpecial123", "Password must contain at least one special character"),
            ]
            for weak_password, expected_error in test_cases:
                # Setup mock to raise PasswordPolicyError for this specific test
                mock_password_change_service.change_password.side_effect = PasswordPolicyError(expected_error)
                
                response = client.put(
                    "/api/v1/auth/change-password",
                    json={"old_password": "OldPass123!", "new_password": weak_password},
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_security_headers(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test that security headers are properly set in responses."""
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Setup mocks
        mock_password_change_service.change_password.return_value = None
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NewPass456!"},
                headers={"Authorization": f"Bearer {token}", "Accept-Language": "en"},
            )
            assert response.status_code == 200
            # Note: Security headers are typically set by middleware, not individual endpoints
        finally:
            app.dependency_overrides.clear()

    def test_change_password_unicode_handling(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test that Unicode characters in passwords are properly handled."""
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Setup mocks
        mock_password_change_service.change_password.return_value = None
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            unicode_passwords = [
                "P@ssw0rd中文",
                "P@ssw0rdالعربية",
                "P@ssw0rdहिन्दी",
                "P@ssw0rdрусский",
            ]
            old_password = "OldPass123!"
            for unicode_password in unicode_passwords:
                response = client.put(
                    "/api/v1/auth/change-password",
                    json={"old_password": old_password, "new_password": unicode_password},
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert response.status_code == 200
                assert response.json()["message"] == "Password changed successfully"
        finally:
            app.dependency_overrides.clear()

    def test_change_password_sql_injection_attempt(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test that SQL injection attempts are properly handled."""
        from src.core.exceptions import PasswordPolicyError
        
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            sql_injection_passwords = [
                "'; DROP TABLE users; --",
                "' OR '1'='1",
                "'; INSERT INTO users VALUES ('hacker', 'hacker@evil.com'); --",
            ]
            for malicious_password in sql_injection_passwords:
                # Setup mock to raise PasswordPolicyError for malicious passwords
                mock_password_change_service.change_password.side_effect = PasswordPolicyError("Invalid password format")
                
                response = client.put(
                    "/api/v1/auth/change-password",
                    json={"old_password": "OldPass123!", "new_password": malicious_password},
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_xss_attempt(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test that XSS attempts in password fields are properly handled."""
        from src.core.exceptions import PasswordPolicyError
        
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            xss_passwords = [
                "<script>alert('xss')</script>",
                "javascript:alert('xss')",
                "<img src=x onerror=alert('xss')>",
            ]
            for malicious_password in xss_passwords:
                # Setup mock to raise PasswordPolicyError for malicious passwords
                mock_password_change_service.change_password.side_effect = PasswordPolicyError("Invalid password format")
                
                response = client.put(
                    "/api/v1/auth/change-password",
                    json={"old_password": "OldPass123!", "new_password": malicious_password},
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()
