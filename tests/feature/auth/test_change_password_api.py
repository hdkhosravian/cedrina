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
from src.infrastructure.database.async_db import get_async_db
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

    def test_change_password_success(self, test_user, mock_db_session, mock_redis_client):
        """Test successful password change with valid credentials."""
        mock_db_session.get.return_value = test_user
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
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
        self, test_user, mock_db_session, mock_redis_client
    ):
        """Test change password fails with incorrect old password (400 status)."""
        mock_db_session.get.return_value = test_user
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
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

    def test_change_password_weak_new_password(self, test_user, mock_db_session, mock_redis_client):
        """Test change password fails with weak new password (422 status)."""
        mock_db_session.get.return_value = test_user
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
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

    def test_change_password_same_password(self, test_user, mock_db_session, mock_redis_client):
        """Test change password fails when new password is same as old (400 status)."""
        mock_db_session.get.return_value = test_user
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
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

    def test_change_password_i18n_english(self, test_user, mock_db_session, mock_redis_client):
        """Test change password with English language support."""
        mock_db_session.get.return_value = test_user
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
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

    def test_change_password_i18n_spanish(self, test_user, mock_db_session, mock_redis_client):
        """Test change password with Spanish language support."""
        mock_db_session.get.return_value = test_user
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
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

    def test_change_password_missing_fields(self, test_user, mock_db_session, mock_redis_client):
        """Test change password fails with missing required fields."""
        mock_db_session.get.return_value = test_user
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
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

    def test_change_password_database_error(self, test_user, mock_db_session, mock_redis_client):
        """Test change password fails when database operations fail."""
        mock_db_session.get.return_value = test_user
        mock_db_session.commit.side_effect = Exception("Database connection failed")
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NewPass456!"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 500
        finally:
            app.dependency_overrides.clear()

    def test_change_password_password_policy_violations(
        self, test_user, mock_db_session, mock_redis_client
    ):
        """Test change password fails with various password policy violations."""
        mock_db_session.get.return_value = test_user
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
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
                response = client.put(
                    "/api/v1/auth/change-password",
                    json={"old_password": "OldPass123!", "new_password": weak_password},
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert response.status_code == 422
                assert expected_error in response.json()["detail"]
        finally:
            app.dependency_overrides.clear()

    def test_change_password_security_headers(self, test_user, mock_db_session, mock_redis_client):
        """Test that security headers are properly set in responses."""
        mock_db_session.get.return_value = test_user
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NewPass456!"},
                headers={"Authorization": f"Bearer {token}", "Accept-Language": "en"},
            )
            assert response.status_code == 200
            assert "Content-Language" in response.headers
            assert response.headers["Content-Language"] == "en"
        finally:
            app.dependency_overrides.clear()

    def test_change_password_unicode_handling(self, test_user, mock_db_session, mock_redis_client):
        """Test that Unicode characters in passwords are properly handled."""
        mock_db_session.get.return_value = test_user
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        pwd_context = CryptContext(
            schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=BCRYPT_WORK_FACTOR
        )
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
                # Use real pwd_context to hash the new password
                test_user.hashed_password = pwd_context.hash(unicode_password)
                old_password = unicode_password
        finally:
            app.dependency_overrides.clear()

    def test_change_password_sql_injection_attempt(
        self, test_user, mock_db_session, mock_redis_client
    ):
        """Test that SQL injection attempts are properly handled."""
        mock_db_session.get.return_value = test_user
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            sql_injection_passwords = [
                "'; DROP TABLE users; --",
                "' OR '1'='1",
                "'; INSERT INTO users VALUES ('hacker', 'hacker@evil.com'); --",
            ]
            for malicious_password in sql_injection_passwords:
                response = client.put(
                    "/api/v1/auth/change-password",
                    json={"old_password": "OldPass123!", "new_password": malicious_password},
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_xss_attempt(self, test_user, mock_db_session, mock_redis_client):
        """Test that XSS attempts in password fields are properly handled."""
        mock_db_session.get.return_value = test_user
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            xss_passwords = [
                "<script>alert('xss')</script>",
                "javascript:alert('xss')",
                "<img src=x onerror=alert('xss')>",
            ]
            for malicious_password in xss_passwords:
                response = client.put(
                    "/api/v1/auth/change-password",
                    json={"old_password": "OldPass123!", "new_password": malicious_password},
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()
