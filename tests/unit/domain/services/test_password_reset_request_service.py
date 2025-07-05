"""Tests for Password Reset Request Service.

These tests verify the password reset request workflow following
Test-Driven Development principles and clean architecture patterns.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock

import pytest

from src.core.exceptions import (
    EmailServiceError,
    ForgotPasswordError,
    RateLimitExceededError,
)
from src.domain.entities.user import User
from src.domain.events.password_reset_events import (
    PasswordResetRequestedEvent,
    PasswordResetFailedEvent,
)
from src.domain.services.password_reset.password_reset_request_service import (
    PasswordResetRequestService,
)
from src.domain.value_objects.reset_token import ResetToken


@pytest.fixture
def mock_user_repository():
    """Mock user repository."""
    return AsyncMock()


@pytest.fixture
def mock_rate_limiting_service():
    """Mock rate limiting service."""
    return AsyncMock()


@pytest.fixture
def mock_token_service():
    """Mock token service."""
    mock = Mock()
    mock.generate_token = AsyncMock()
    return mock


@pytest.fixture
def mock_email_service():
    """Mock email service."""
    return AsyncMock()


@pytest.fixture
def mock_event_publisher():
    """Mock event publisher."""
    return AsyncMock()


@pytest.fixture
def service(
    mock_user_repository,
    mock_rate_limiting_service,
    mock_token_service,
    mock_email_service,
    mock_event_publisher,
):
    """Create password reset request service with mocked dependencies."""
    return PasswordResetRequestService(
        user_repository=mock_user_repository,
        rate_limiting_service=mock_rate_limiting_service,
        token_service=mock_token_service,
        email_service=mock_email_service,
        event_publisher=mock_event_publisher,
    )


@pytest.fixture
def valid_user():
    """Create a valid user for testing."""
    user = User(
        id=1,
        username="testuser",
        email="test@example.com",
        hashed_password="$2b$12$hash",
        is_active=True,
        email_confirmed=True,
        created_at=datetime.now(timezone.utc),
    )
    return user


@pytest.fixture
def reset_token():
    """Create a reset token for testing."""
    return ResetToken.generate()


class TestPasswordResetRequestService:
    """Test suite for PasswordResetRequestService."""
    
    @pytest.mark.asyncio
    async def test_successful_password_reset_request(
        self,
        service,
        mock_user_repository,
        mock_rate_limiting_service,
        mock_token_service,
        mock_email_service,
        mock_event_publisher,
        valid_user,
        reset_token,
    ):
        """Test successful password reset request workflow."""
        # Arrange
        email = "test@example.com"
        language = "en"
        
        mock_user_repository.get_by_email.return_value = valid_user
        mock_rate_limiting_service.is_user_rate_limited.return_value = False
        mock_token_service.generate_token.return_value = reset_token
        mock_user_repository.save.return_value = valid_user
        mock_email_service.send_password_reset_email.return_value = True
        
        # Act
        result = await service.request_password_reset(email, language)
        
        # Assert
        assert result["status"] == "success"
        assert "password_reset_email_sent" in result["message"] or result["message"]
        
        # Verify all dependencies were called correctly
        mock_user_repository.get_by_email.assert_called_once_with(email)
        mock_rate_limiting_service.is_user_rate_limited.assert_called_once_with(valid_user.id)
        mock_token_service.generate_token.assert_called_once_with(valid_user)
        mock_user_repository.save.assert_called()
        mock_email_service.send_password_reset_email.assert_called_once()
        mock_rate_limiting_service.record_attempt.assert_called_once_with(valid_user.id)
        mock_event_publisher.publish.assert_called_once()
        
        # Verify event was published correctly
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert isinstance(published_event, PasswordResetRequestedEvent)
        assert published_event.user_id == valid_user.id
        assert published_event.email == email
    
    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(
        self,
        service,
        mock_user_repository,
        mock_rate_limiting_service,
        valid_user,
    ):
        """Test rate limit exceeded scenario."""
        # Arrange
        email = "test@example.com"
        
        mock_user_repository.get_by_email.return_value = valid_user
        mock_rate_limiting_service.is_user_rate_limited.return_value = True
        
        # Act & Assert
        with pytest.raises(RateLimitExceededError):
            await service.request_password_reset(email)
        
        # Verify rate limit was checked but no further processing occurred
        mock_rate_limiting_service.is_user_rate_limited.assert_called_once_with(valid_user.id)
        mock_rate_limiting_service.record_attempt.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_user_not_found_returns_success(
        self,
        service,
        mock_user_repository,
        mock_rate_limiting_service,
        mock_event_publisher,
    ):
        """Test that non-existent user returns success (security)."""
        # Arrange
        email = "nonexistent@example.com"
        
        mock_user_repository.get_by_email.return_value = None
        
        # Act
        result = await service.request_password_reset(email)
        
        # Assert
        assert result["status"] == "success"
        
        # Verify no rate limiting or email sending occurred
        mock_rate_limiting_service.is_user_rate_limited.assert_not_called()
        mock_event_publisher.publish.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_inactive_user_returns_success(
        self,
        service,
        mock_user_repository,
        mock_rate_limiting_service,
        valid_user,
    ):
        """Test that inactive user returns success (security)."""
        # Arrange
        email = "test@example.com"
        valid_user.is_active = False
        
        mock_user_repository.get_by_email.return_value = valid_user
        mock_rate_limiting_service.is_user_rate_limited.return_value = False
        
        # Act
        result = await service.request_password_reset(email)
        
        # Assert
        assert result["status"] == "success"
    
    @pytest.mark.asyncio
    async def test_email_service_failure(
        self,
        service,
        mock_user_repository,
        mock_rate_limiting_service,
        mock_token_service,
        mock_email_service,
        mock_event_publisher,
        valid_user,
        reset_token,
    ):
        """Test email service failure handling."""
        # Arrange
        email = "test@example.com"
        
        mock_user_repository.get_by_email.return_value = valid_user
        mock_rate_limiting_service.is_user_rate_limited.return_value = False
        mock_token_service.generate_token.return_value = reset_token
        mock_email_service.send_password_reset_email.side_effect = EmailServiceError("Email failed")
        
        # Act & Assert
        with pytest.raises(EmailServiceError):
            await service.request_password_reset(email)
        
        # Verify token was invalidated due to email failure
        mock_token_service.invalidate_token.assert_called_once()
        
        # Verify failure event was published
        mock_event_publisher.publish.assert_called_once()
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert isinstance(published_event, PasswordResetFailedEvent)
    
    @pytest.mark.asyncio
    async def test_correlation_id_tracking(
        self,
        service,
        mock_user_repository,
        mock_rate_limiting_service,
        mock_token_service,
        mock_email_service,
        mock_event_publisher,
        valid_user,
        reset_token,
    ):
        """Test correlation ID is properly tracked through the workflow."""
        # Arrange
        email = "test@example.com"
        correlation_id = "test-correlation-123"
        
        mock_user_repository.get_by_email.return_value = valid_user
        mock_rate_limiting_service.is_user_rate_limited.return_value = False
        mock_token_service.generate_token.return_value = reset_token
        mock_email_service.send_password_reset_email.return_value = True
        
        # Act
        await service.request_password_reset(
            email, correlation_id=correlation_id
        )
        
        # Assert
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert published_event.correlation_id == correlation_id
    
    @pytest.mark.asyncio
    async def test_security_tracking_parameters(
        self,
        service,
        mock_user_repository,
        mock_rate_limiting_service,
        mock_token_service,
        mock_email_service,
        mock_event_publisher,
        valid_user,
        reset_token,
    ):
        """Test security tracking parameters are included in events."""
        # Arrange
        email = "test@example.com"
        user_agent = "Mozilla/5.0 Test Browser"
        ip_address = "192.168.1.1"
        
        mock_user_repository.get_by_email.return_value = valid_user
        mock_rate_limiting_service.is_user_rate_limited.return_value = False
        mock_token_service.generate_token.return_value = reset_token
        mock_email_service.send_password_reset_email.return_value = True
        
        # Act
        await service.request_password_reset(
            email, user_agent=user_agent, ip_address=ip_address
        )
        
        # Assert
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert published_event.user_agent == user_agent
        assert published_event.ip_address == ip_address
    
    @pytest.mark.asyncio
    async def test_unexpected_error_handling(
        self,
        service,
        mock_user_repository,
        mock_rate_limiting_service,
        mock_event_publisher,
        valid_user,
    ):
        """Test handling of unexpected errors."""
        # Arrange
        email = "test@example.com"
        
        mock_user_repository.get_by_email.return_value = valid_user
        mock_rate_limiting_service.is_user_rate_limited.return_value = False
        mock_user_repository.save.side_effect = Exception("Database error")
        
        # Act & Assert
        with pytest.raises(ForgotPasswordError):
            await service.request_password_reset(email)
        
        # Verify failure event was published
        mock_event_publisher.publish.assert_called_once()
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert isinstance(published_event, PasswordResetFailedEvent)
        assert published_event.failure_reason == "unexpected_error" 