"""Tests for EmailConfirmationService."""

import pytest
from unittest.mock import AsyncMock, Mock
from datetime import datetime, timezone

from src.core.exceptions import AuthenticationError
from src.domain.entities.user import User, Role
from src.domain.services.email_confirmation.email_confirmation_service import EmailConfirmationService
from src.infrastructure.services.email.email_service import EmailService


class TestEmailConfirmationService:
    """Test cases for EmailConfirmationService."""

    @pytest.fixture
    def mock_user_repository(self):
        """Mock user repository."""
        return AsyncMock()

    @pytest.fixture
    def mock_event_publisher(self):
        """Mock event publisher."""
        return AsyncMock()

    @pytest.fixture
    def mock_email_service(self):
        """Mock email service."""
        return AsyncMock(spec=EmailService)

    @pytest.fixture
    def email_confirmation_service(self, mock_user_repository, mock_event_publisher, mock_email_service):
        """Email confirmation service instance."""
        return EmailConfirmationService(
            user_repository=mock_user_repository,
            event_publisher=mock_event_publisher,
            email_service=mock_email_service,
        )

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
            email_confirmation_token=None,
        )

    @pytest.mark.asyncio
    async def test_send_confirmation_email_success(
        self, email_confirmation_service, mock_user_repository, mock_email_service, test_user
    ):
        """Test successful email confirmation sending."""
        # Arrange
        mock_user_repository.update.return_value = test_user
        mock_email_service.send_confirmation_email.return_value = True

        # Act
        token = await email_confirmation_service.send_confirmation_email(
            user=test_user,
            language="en",
            correlation_id="test-correlation-id",
        )

        # Assert
        assert token is not None
        assert len(token) > 0
        assert test_user.email_confirmation_token == token
        mock_user_repository.update.assert_called_once_with(test_user)
        mock_email_service.send_confirmation_email.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_confirmation_email_failure(
        self, email_confirmation_service, mock_user_repository, mock_email_service, test_user
    ):
        """Test email confirmation sending failure."""
        # Arrange
        mock_user_repository.update.return_value = test_user
        mock_email_service.send_confirmation_email.side_effect = Exception("Email sending failed")

        # Act & Assert
        with pytest.raises(AuthenticationError) as exc_info:
            await email_confirmation_service.send_confirmation_email(
                user=test_user,
                language="en",
                correlation_id="test-correlation-id",
            )

        assert "email_confirmation_send_failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_confirm_email_success(
        self, email_confirmation_service, mock_user_repository, test_user
    ):
        """Test successful email confirmation."""
        # Arrange
        test_token = "test_confirmation_token"
        test_user.email_confirmation_token = test_token
        mock_user_repository.get_by_email_confirmation_token.return_value = test_user
        mock_user_repository.update.return_value = test_user

        # Act
        confirmed_user = await email_confirmation_service.confirm_email(
            token=test_token,
            correlation_id="test-correlation-id",
        )

        # Assert
        assert confirmed_user.email_confirmed is True
        assert confirmed_user.email_confirmed_at is not None
        assert confirmed_user.email_confirmation_token is None
        mock_user_repository.get_by_email_confirmation_token.assert_called_once_with(test_token)
        mock_user_repository.update.assert_called_once_with(test_user)

    @pytest.mark.asyncio
    async def test_confirm_email_invalid_token(
        self, email_confirmation_service, mock_user_repository
    ):
        """Test email confirmation with invalid token."""
        # Arrange
        test_token = "invalid_token"
        mock_user_repository.get_by_email_confirmation_token.return_value = None

        # Act & Assert
        with pytest.raises(AuthenticationError) as exc_info:
            await email_confirmation_service.confirm_email(
                token=test_token,
                correlation_id="test-correlation-id",
            )

        assert "invalid_email_confirmation_token" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_resend_confirmation_email_success(
        self, email_confirmation_service, mock_user_repository, test_user
    ):
        """Test successful resend confirmation email."""
        # Arrange
        test_user.email_confirmed = False
        mock_user_repository.get_by_email.return_value = test_user
        email_confirmation_service.send_confirmation_email = AsyncMock(return_value="new_token")

        # Act
        result = await email_confirmation_service.resend_confirmation_email(
            email="test@example.com",
            language="en",
            correlation_id="test-correlation-id",
        )

        # Assert
        assert result is True
        mock_user_repository.get_by_email.assert_called_once_with("test@example.com")
        email_confirmation_service.send_confirmation_email.assert_called_once()

    @pytest.mark.asyncio
    async def test_resend_confirmation_email_nonexistent_user(
        self, email_confirmation_service, mock_user_repository
    ):
        """Test resend confirmation email for non-existent user."""
        # Arrange
        mock_user_repository.get_by_email.return_value = None

        # Act
        result = await email_confirmation_service.resend_confirmation_email(
            email="nonexistent@example.com",
            language="en",
            correlation_id="test-correlation-id",
        )

        # Assert - Should return True to prevent email enumeration
        assert result is True
        mock_user_repository.get_by_email.assert_called_once_with("nonexistent@example.com")

    @pytest.mark.asyncio
    async def test_resend_confirmation_email_already_confirmed(
        self, email_confirmation_service, mock_user_repository, test_user
    ):
        """Test resend confirmation email for already confirmed user."""
        # Arrange
        test_user.email_confirmed = True
        mock_user_repository.get_by_email.return_value = test_user

        # Act
        result = await email_confirmation_service.resend_confirmation_email(
            email="test@example.com",
            language="en",
            correlation_id="test-correlation-id",
        )

        # Assert - Should return True but not send email
        assert result is True
        mock_user_repository.get_by_email.assert_called_once_with("test@example.com")

    @pytest.mark.asyncio
    async def test_generate_confirmation_token(self, email_confirmation_service, test_user):
        """Test confirmation token generation."""
        # Act
        token1 = await email_confirmation_service.generate_confirmation_token(test_user)
        token2 = await email_confirmation_service.generate_confirmation_token(test_user)

        # Assert
        assert token1 is not None
        assert len(token1) > 0
        assert token2 is not None
        assert len(token2) > 0
        assert token1 != token2  # Tokens should be unique

    @pytest.mark.asyncio
    async def test_is_confirmation_required_enabled(self, email_confirmation_service, monkeypatch):
        """Test is_confirmation_required when feature is enabled."""
        # Arrange
        from src.core.config import settings
        monkeypatch.setattr(settings, "EMAIL_CONFIRMATION_ENABLED", True)

        # Act
        result = await email_confirmation_service.is_confirmation_required()

        # Assert
        assert result is True

    @pytest.mark.asyncio
    async def test_is_confirmation_required_disabled(self, email_confirmation_service, monkeypatch):
        """Test is_confirmation_required when feature is disabled."""
        # Arrange
        from src.core.config import settings
        monkeypatch.setattr(settings, "EMAIL_CONFIRMATION_ENABLED", False)

        # Act
        result = await email_confirmation_service.is_confirmation_required()

        # Assert
        assert result is False