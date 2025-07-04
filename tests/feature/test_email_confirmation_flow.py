"""Feature tests for email confirmation flow."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

from src.main import app
from src.domain.entities.user import User, Role


class TestEmailConfirmationFlow:
    """Test cases for email confirmation feature flow."""

    @pytest.fixture
    def client(self):
        """Test client fixture."""
        return TestClient(app)

    @pytest.fixture
    def test_user(self):
        """Test user fixture."""
        return User(
            id=1,
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_password",
            role=Role.USER,
            is_active=False,
            email_confirmed=False,
            email_confirmation_token="test_token_123",
        )

    def test_email_confirmation_enabled_registration_creates_inactive_user(
        self, client, monkeypatch
    ):
        """Test that with email confirmation enabled, registration creates inactive user."""
        # Arrange
        monkeypatch.setenv("EMAIL_CONFIRMATION_ENABLED", "true")
        
        with patch("src.domain.services.authentication.user_registration_service.UserRegistrationService") as mock_service:
            mock_user = User(
                id=1,
                username="testuser", 
                email="test@example.com",
                hashed_password="hashed_password",
                role=Role.USER,
                is_active=False,  # Should be inactive when email confirmation is enabled
                email_confirmed=False,
            )
            mock_service.return_value.register_user.return_value = mock_user

            # Act
            response = client.post(
                "/auth/register",
                json={
                    "username": "testuser",
                    "email": "test@example.com", 
                    "password": "SecurePass123!",
                }
            )

            # Assert
            assert response.status_code == 201
            data = response.json()
            assert data["user"]["is_active"] is False

    def test_email_confirmation_disabled_registration_creates_active_user(
        self, client, monkeypatch
    ):
        """Test that with email confirmation disabled, registration creates active user."""
        # Arrange
        monkeypatch.setenv("EMAIL_CONFIRMATION_ENABLED", "false")
        
        with patch("src.domain.services.authentication.user_registration_service.UserRegistrationService") as mock_service:
            mock_user = User(
                id=1,
                username="testuser",
                email="test@example.com", 
                hashed_password="hashed_password",
                role=Role.USER,
                is_active=True,  # Should be active when email confirmation is disabled
                email_confirmed=False,
            )
            mock_service.return_value.register_user.return_value = mock_user

            # Act
            response = client.post(
                "/auth/register",
                json={
                    "username": "testuser",
                    "email": "test@example.com",
                    "password": "SecurePass123!",
                }
            )

            # Assert
            assert response.status_code == 201
            data = response.json()
            assert data["user"]["is_active"] is True

    def test_confirm_email_success(self, client):
        """Test successful email confirmation."""
        # Arrange
        with patch("src.domain.services.email_confirmation.email_confirmation_service.EmailConfirmationService") as mock_service:
            mock_user = User(
                id=1,
                username="testuser",
                email="test@example.com",
                hashed_password="hashed_password", 
                role=Role.USER,
                is_active=True,
                email_confirmed=True,
                email_confirmed_at="2025-01-27T10:00:00Z",
            )
            mock_service.return_value.confirm_email.return_value = mock_user

            # Act
            response = client.post(
                "/auth/confirm-email/confirm",
                json={"token": "valid_token_123"}
            )

            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["message"] == "Email confirmed successfully"
            assert data["user"]["email_confirmed"] is True

    def test_confirm_email_invalid_token(self, client):
        """Test email confirmation with invalid token."""
        # Arrange
        with patch("src.domain.services.email_confirmation.email_confirmation_service.EmailConfirmationService") as mock_service:
            from src.core.exceptions import AuthenticationError
            mock_service.return_value.confirm_email.side_effect = AuthenticationError("Invalid token")

            # Act
            response = client.post(
                "/auth/confirm-email/confirm",
                json={"token": "invalid_token"}
            )

            # Assert
            assert response.status_code == 400
            assert "Invalid token" in response.json()["detail"]

    def test_resend_confirmation_email_success(self, client):
        """Test successful resend confirmation email."""
        # Arrange
        with patch("src.domain.services.email_confirmation.email_confirmation_service.EmailConfirmationService") as mock_service:
            mock_service.return_value.resend_confirmation_email.return_value = True

            # Act
            response = client.post(
                "/auth/confirm-email/resend",
                json={"email": "test@example.com"}
            )

            # Assert
            assert response.status_code == 200
            data = response.json()
            assert "receive a confirmation email" in data["message"]

    def test_login_blocked_when_email_not_confirmed(self, client, monkeypatch):
        """Test that login is blocked when email confirmation is enabled and email not confirmed."""
        # Arrange
        monkeypatch.setenv("EMAIL_CONFIRMATION_ENABLED", "true")
        
        with patch("src.domain.services.authentication.user_authentication_service.UserAuthenticationService") as mock_service:
            from src.core.exceptions import AuthenticationError
            mock_service.return_value.authenticate_user.side_effect = AuthenticationError(
                "Please confirm your email address before logging in"
            )

            # Act
            response = client.post(
                "/auth/login",
                json={
                    "username": "testuser",
                    "password": "SecurePass123!",
                }
            )

            # Assert
            assert response.status_code == 400
            assert "confirm your email" in response.json()["detail"]

    def test_login_allowed_when_email_confirmed(self, client, monkeypatch):
        """Test that login is allowed when email is confirmed."""
        # Arrange
        monkeypatch.setenv("EMAIL_CONFIRMATION_ENABLED", "true")
        
        with patch("src.domain.services.authentication.user_authentication_service.UserAuthenticationService") as mock_service:
            mock_user = User(
                id=1,
                username="testuser",
                email="test@example.com",
                hashed_password="hashed_password",
                role=Role.USER,
                is_active=True,
                email_confirmed=True,
            )
            mock_service.return_value.authenticate_user.return_value = mock_user
            
            with patch("src.domain.services.authentication.token_service.TokenService") as mock_token_service:
                mock_token_service.return_value.create_token_pair.return_value = {
                    "access_token": "access_token",
                    "refresh_token": "refresh_token",
                    "token_type": "bearer",
                    "expires_in": 900,
                }

                # Act
                response = client.post(
                    "/auth/login",
                    json={
                        "username": "testuser",
                        "password": "SecurePass123!",
                    }
                )

                # Assert
                assert response.status_code == 200
                data = response.json()
                assert "access_token" in data["tokens"]
                assert data["user"]["email_confirmed"] is True

    def test_login_allowed_when_email_confirmation_disabled(self, client, monkeypatch):
        """Test that login is allowed when email confirmation is disabled."""
        # Arrange
        monkeypatch.setenv("EMAIL_CONFIRMATION_ENABLED", "false")
        
        with patch("src.domain.services.authentication.user_authentication_service.UserAuthenticationService") as mock_service:
            mock_user = User(
                id=1,
                username="testuser",
                email="test@example.com",
                hashed_password="hashed_password",
                role=Role.USER,
                is_active=True,
                email_confirmed=False,  # Email not confirmed but feature disabled
            )
            mock_service.return_value.authenticate_user.return_value = mock_user
            
            with patch("src.domain.services.authentication.token_service.TokenService") as mock_token_service:
                mock_token_service.return_value.create_token_pair.return_value = {
                    "access_token": "access_token",
                    "refresh_token": "refresh_token",
                    "token_type": "bearer",
                    "expires_in": 900,
                }

                # Act
                response = client.post(
                    "/auth/login",
                    json={
                        "username": "testuser",
                        "password": "SecurePass123!",
                    }
                )

                # Assert
                assert response.status_code == 200
                data = response.json()
                assert "access_token" in data["tokens"]