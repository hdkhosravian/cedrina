"""Tests for ForgotPasswordService.

This module tests the forgot password domain service functionality including:
- Password reset request handling with security controls
- Token validation and password reset operations
- Rate limiting and abuse prevention
- Email coordination and error handling
- Cleanup of expired tokens

All tests follow TDD principles and cover real-world scenarios.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock, patch

from src.core.exceptions import (
    EmailServiceError,
    ForgotPasswordError,
    PasswordResetError,
    RateLimitExceededError,
    UserNotFoundError,
)
from src.domain.entities.user import User, Role
from src.domain.services.auth.password_reset_token_service import PasswordResetTokenService
from src.domain.services.forgot_password.forgot_password_service import ForgotPasswordService
from src.domain.services.forgot_password.password_reset_email_service import (
    PasswordResetEmailService,
)
from src.infrastructure.repositories.user_repository import UserRepository


class TestForgotPasswordService:
    """Test suite for ForgotPasswordService functionality."""

    @pytest.fixture
    def mock_user_repository(self):
        """Mock user repository."""
        return Mock(spec=UserRepository)

    @pytest.fixture
    def mock_email_service(self):
        """Mock password reset email service."""
        return Mock(spec=PasswordResetEmailService)

    @pytest.fixture
    def mock_token_service(self):
        """Mock password reset token service."""
        return Mock(spec=PasswordResetTokenService)

    @pytest.fixture
    def test_user(self):
        """Create a test user."""
        return User(
            id=1,
            username="testuser",
            email="test@example.com",
            hashed_password="$2b$12$hashedpassword",
            role=Role.USER,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )

    @pytest.fixture
    def service(self, mock_user_repository, mock_email_service, mock_token_service):
        """Create ForgotPasswordService with mocked dependencies."""
        return ForgotPasswordService(
            user_repository=mock_user_repository,
            email_service=mock_email_service,
            token_service=mock_token_service,
        )

    @pytest.mark.asyncio
    async def test_request_password_reset_success(
        self, service, mock_user_repository, mock_email_service, mock_token_service, test_user
    ):
        """Test successful password reset request."""
        # Arrange
        email = "test@example.com"
        language = "en"
        token = "secure_token_123"

        mock_user_repository.get_by_email.return_value = test_user
        mock_token_service.generate_token.return_value = token
        mock_email_service.send_password_reset_email = AsyncMock()
        mock_user_repository.save = AsyncMock()

        # Act
        result = await service.request_password_reset(email, language)

        # Assert
        assert result["status"] == "success"
        assert "message" in result
        mock_user_repository.get_by_email.assert_called_once_with(email)
        mock_token_service.generate_token.assert_called_once_with(test_user)
        mock_email_service.send_password_reset_email.assert_called_once_with(
            user=test_user,
            token=token,
            language=language,
        )
        mock_user_repository.save.assert_called_once_with(test_user)

    @pytest.mark.asyncio
    async def test_request_password_reset_user_not_found(
        self, service, mock_user_repository, mock_email_service, mock_token_service
    ):
        """Test password reset request for non-existent user."""
        # Arrange
        email = "nonexistent@example.com"
        language = "en"

        mock_user_repository.get_by_email.return_value = None

        # Act
        result = await service.request_password_reset(email, language)

        # Assert
        # Should return success to prevent email enumeration
        assert result["status"] == "success"
        assert "message" in result
        mock_user_repository.get_by_email.assert_called_once_with(email)
        mock_token_service.generate_token.assert_not_called()
        mock_email_service.send_password_reset_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_request_password_reset_inactive_user(
        self, service, mock_user_repository, mock_email_service, mock_token_service, test_user
    ):
        """Test password reset request for inactive user."""
        # Arrange
        email = "test@example.com"
        language = "en"
        test_user.is_active = False

        mock_user_repository.get_by_email.return_value = test_user

        # Act
        result = await service.request_password_reset(email, language)

        # Assert
        # Should return success to prevent account enumeration
        assert result["status"] == "success"
        assert "message" in result
        mock_user_repository.get_by_email.assert_called_once_with(email)
        mock_token_service.generate_token.assert_not_called()
        mock_email_service.send_password_reset_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_request_password_reset_email_failure(
        self, service, mock_user_repository, mock_email_service, mock_token_service, test_user
    ):
        """Test password reset request with email sending failure."""
        # Arrange
        email = "test@example.com"
        language = "en"
        token = "secure_token_123"

        mock_user_repository.get_by_email.return_value = test_user
        mock_token_service.generate_token.return_value = token
        mock_email_service.send_password_reset_email = AsyncMock(
            side_effect=EmailServiceError("Email delivery failed")
        )
        mock_user_repository.save = AsyncMock()

        # Act & Assert
        with pytest.raises(EmailServiceError):
            await service.request_password_reset(email, language)

        # Verify token was cleared due to email failure
        mock_token_service.clear_token.assert_called_once_with(test_user)
        mock_user_repository.save.assert_called_with(test_user)

    @pytest.mark.asyncio
    async def test_reset_password_success(
        self, service, mock_user_repository, mock_token_service, test_user
    ):
        """Test successful password reset."""
        # Arrange
        token = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        new_password = "NewPassword123!"
        language = "en"

        mock_user_repository.get_by_reset_token.return_value = test_user
        mock_token_service.is_token_valid.return_value = True
        mock_user_repository.save = AsyncMock()

        with patch("src.domain.services.forgot_password.forgot_password_service.validate_password_strength", return_value=True), \
             patch("src.domain.services.forgot_password.forgot_password_service.hash_password", return_value="new_hashed_password") as mock_hash:

            # Act
            result = await service.reset_password(token, new_password, language)

            # Assert
            assert result["status"] == "success"
            assert "message" in result
            mock_user_repository.get_by_reset_token.assert_called_once_with(token)
            mock_token_service.is_token_valid.assert_called_once_with(test_user, token)
            mock_token_service.clear_token.assert_called_once_with(test_user)
            mock_hash.assert_called_once_with(new_password)
            assert test_user.hashed_password == "new_hashed_password"
            mock_user_repository.save.assert_called_once_with(test_user)

    @pytest.mark.asyncio
    async def test_reset_password_invalid_token_format(
        self, service, mock_user_repository, mock_token_service
    ):
        """Test password reset with invalid token format."""
        # Arrange
        invalid_token = "short_token"  # Too short
        new_password = "NewPassword123!"
        language = "en"

        # Act & Assert
        with pytest.raises(PasswordResetError):
            await service.reset_password(invalid_token, new_password, language)

        mock_user_repository.get_by_reset_token.assert_not_called()

    @pytest.mark.asyncio
    async def test_reset_password_token_not_found(
        self, service, mock_user_repository, mock_token_service
    ):
        """Test password reset with unknown token."""
        # Arrange
        token = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        new_password = "NewPassword123!"
        language = "en"

        mock_user_repository.get_by_reset_token.return_value = None

        # Act & Assert
        with pytest.raises(PasswordResetError):
            await service.reset_password(token, new_password, language)

        mock_user_repository.get_by_reset_token.assert_called_once_with(token)

    @pytest.mark.asyncio
    async def test_reset_password_invalid_token(
        self, service, mock_user_repository, mock_token_service, test_user
    ):
        """Test password reset with invalid/expired token."""
        # Arrange
        token = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
        new_password = "NewPassword123!"
        language = "en"

        mock_user_repository.get_by_reset_token.return_value = test_user
        mock_token_service.is_token_valid.return_value = False
        mock_user_repository.save = AsyncMock()

        # Act & Assert
        with pytest.raises(PasswordResetError):
            await service.reset_password(token, new_password, language)

        mock_token_service.clear_token.assert_called_once_with(test_user)
        mock_user_repository.save.assert_called_once_with(test_user)

    @pytest.mark.asyncio
    async def test_reset_password_weak_password(
        self, service, mock_user_repository, mock_token_service, test_user
    ):
        """Test password reset with weak password."""
        # Arrange
        token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        weak_password = "123"
        language = "en"

        mock_user_repository.get_by_reset_token.return_value = test_user
        mock_token_service.is_token_valid.return_value = True
        mock_user_repository.save = AsyncMock()

        with patch("src.domain.services.forgot_password.forgot_password_service.validate_password_strength", return_value=False):
            # Act & Assert
            with pytest.raises(PasswordResetError):
                await service.reset_password(token, weak_password, language)

            mock_token_service.clear_token.assert_called_once_with(test_user)
            mock_user_repository.save.assert_called_once_with(test_user)

    @pytest.mark.asyncio
    async def test_cleanup_expired_tokens(
        self, service, mock_user_repository, mock_token_service
    ):
        """Test cleanup of expired password reset tokens."""
        # Arrange
        expired_user1 = User(
            id=1,
            username="user1",
            email="user1@example.com",
            password_reset_token="token1",
            password_reset_token_expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        expired_user2 = User(
            id=2,
            username="user2",
            email="user2@example.com",
            password_reset_token="token2",
            password_reset_token_expires_at=datetime.now(timezone.utc) - timedelta(hours=2),
        )
        valid_user = User(
            id=3,
            username="user3",
            email="user3@example.com",
            password_reset_token="token3",
            password_reset_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        mock_user_repository.get_users_with_reset_tokens.return_value = [
            expired_user1,
            expired_user2,
            valid_user,
        ]
        mock_token_service.is_token_expired.side_effect = lambda user: user in [expired_user1, expired_user2]
        mock_user_repository.save = AsyncMock()

        # Act
        cleaned_count = await service.cleanup_expired_tokens()

        # Assert
        assert cleaned_count == 2
        mock_user_repository.get_users_with_reset_tokens.assert_called_once()
        assert mock_token_service.clear_token.call_count == 2
        mock_token_service.clear_token.assert_any_call(expired_user1)
        mock_token_service.clear_token.assert_any_call(expired_user2)
        assert mock_user_repository.save.call_count == 2

    @pytest.mark.asyncio
    async def test_rate_limiting(
        self, service, mock_user_repository, mock_email_service, mock_token_service, test_user
    ):
        """Test rate limiting prevents frequent requests."""
        # Arrange
        email = "test@example.com"
        language = "en"

        mock_user_repository.get_by_email.return_value = test_user

        # First request should succeed
        token = "secure_token_123"
        mock_token_service.generate_token.return_value = token
        mock_email_service.send_password_reset_email = AsyncMock()
        mock_user_repository.save = AsyncMock()

        # Act - First request
        result1 = await service.request_password_reset(email, language)

        # Assert first request succeeds
        assert result1["status"] == "success"

        # Act - Second request immediately (should be rate limited)
        with pytest.raises(RateLimitExceededError):
            await service.request_password_reset(email, language)

    @pytest.mark.asyncio
    async def test_reset_password_with_exception_clears_token(
        self, service, mock_user_repository, mock_token_service, test_user
    ):
        """Test that token is cleared even if password update fails."""
        # Arrange
        token = "9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba"
        new_password = "NewPassword123!"
        language = "en"

        mock_user_repository.get_by_reset_token.return_value = test_user
        mock_token_service.is_token_valid.return_value = True
        mock_user_repository.save = AsyncMock(side_effect=Exception("Database error"))

        with patch("src.domain.services.forgot_password.forgot_password_service.validate_password_strength", return_value=True), \
             patch("src.domain.services.forgot_password.forgot_password_service.hash_password", return_value="new_hashed_password"):

            # Act & Assert
            with pytest.raises(Exception):
                await service.reset_password(token, new_password, language)

            # Verify token was cleared despite the exception
            mock_token_service.clear_token.assert_called_with(test_user) 