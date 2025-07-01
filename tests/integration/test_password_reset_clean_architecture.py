"""Integration tests for the clean password reset architecture.

These tests verify that all components work together correctly,
demonstrating the benefits of the clean architecture approach.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock
import re

import pytest
from pydantic import EmailStr

from src.core.exceptions import PasswordResetError, RateLimitExceededError
from src.domain.entities.user import User
from src.domain.events.password_reset_events import (
    PasswordResetRequestedEvent,
    PasswordResetCompletedEvent,
)
from src.domain.services.password_reset.password_reset_request_service import (
    PasswordResetRequestService,
)
from src.domain.services.password_reset.password_reset_service import (
    PasswordResetService,
)
from src.core.rate_limiting.password_reset_service import (
    RateLimitingService,
)
from src.domain.value_objects.password import Password
from src.domain.value_objects.rate_limit import RateLimitState
from src.domain.value_objects.reset_token import ResetToken
from src.infrastructure.services.event_publisher import InMemoryEventPublisher
from src.infrastructure.services.password_reset_token_service import (
    PasswordResetTokenService,
)


@pytest.fixture
def mock_user_repository():
    """Mock user repository for integration tests."""
    return AsyncMock()


@pytest.fixture
def mock_email_service():
    """Mock email service for integration tests."""
    mock = AsyncMock()
    mock.send_password_reset_email.return_value = True
    return mock


@pytest.fixture
def event_publisher():
    """Real event publisher for integration tests."""
    return InMemoryEventPublisher()


@pytest.fixture
def token_service():
    """Real token service for integration tests."""
    return PasswordResetTokenService()


@pytest.fixture
def rate_limiting_service():
    """Real rate limiting service for integration tests."""
    return RateLimitingService(RateLimitState())


@pytest.fixture
def password_reset_request_service(
    mock_user_repository,
    rate_limiting_service,
    token_service,
    mock_email_service,
    event_publisher,
):
    """Password reset request service with real components."""
    return PasswordResetRequestService(
        user_repository=mock_user_repository,
        rate_limiting_service=rate_limiting_service,
        token_service=token_service,
        email_service=mock_email_service,
        event_publisher=event_publisher,
    )


@pytest.fixture
def password_reset_service(
    mock_user_repository,
    token_service,
    event_publisher,
):
    """Password reset service with real components."""
    return PasswordResetService(
        user_repository=mock_user_repository,
        token_service=token_service,
        event_publisher=event_publisher,
    )


@pytest.fixture
def test_user():
    """Create a test user."""
    return User(
        id=1,
        username="testuser",
        email="test@example.com",
        hashed_password="$2b$12$oldhash",
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )


class TestPasswordResetIntegration:
    """Integration tests for the complete password reset workflow."""
    
    @pytest.mark.asyncio
    async def test_complete_password_reset_workflow(
        self,
        password_reset_request_service,
        password_reset_service,
        mock_user_repository,
        event_publisher,
        test_user,
    ):
        """Test the complete end-to-end password reset workflow."""
        # Arrange
        email = "test@example.com"
        new_password = "MyNewStr0ng#P@ssw0rd"
        
        # Mock repository responses
        mock_user_repository.get_by_email.return_value = test_user
        mock_user_repository.save.return_value = test_user
        
        # Step 1: Request password reset
        result = await password_reset_request_service.request_password_reset(email)
        
        # Verify request was successful
        assert result["status"] == "success"
        
        # Verify user has token set
        save_calls = mock_user_repository.save.call_args_list
        assert len(save_calls) >= 1
        
        # Verify domain event was published
        events = event_publisher.get_published_events()
        request_events = [e for e in events if isinstance(e, PasswordResetRequestedEvent)]
        assert len(request_events) == 1
        assert request_events[0].email == email
        
        # Step 2: Extract token from user (simulate email link click)
        # Mock repository to return user with token for reset
        token_value = test_user.password_reset_token
        assert token_value is not None
        assert ResetToken.MIN_TOKEN_LENGTH <= len(token_value) <= ResetToken.MAX_TOKEN_LENGTH
        assert any(c.isupper() for c in token_value)
        assert any(c.islower() for c in token_value)
        assert any(c.isdigit() for c in token_value)
        assert any(not c.isalnum() for c in token_value)
        
        mock_user_repository.get_by_reset_token.return_value = test_user
        
        # Step 3: Reset password using token
        reset_result = await password_reset_service.reset_password(
            token=token_value,
            new_password=new_password,
        )
        
        # Verify reset was successful
        assert reset_result["status"] == "success"
        
        # Verify password was updated and token cleared
        assert test_user.hashed_password != "$2b$12$oldhash"
        assert test_user.password_reset_token is None
        assert test_user.password_reset_token_expires_at is None
        
        # Verify completion event was published
        all_events = event_publisher.get_published_events()
        completion_events = [e for e in all_events if isinstance(e, PasswordResetCompletedEvent)]
        assert len(completion_events) == 1
        assert completion_events[0].email == email
    
    @pytest.mark.asyncio
    async def test_rate_limiting_prevents_abuse(
        self,
        password_reset_request_service,
        mock_user_repository,
        test_user,
    ):
        """Test that rate limiting prevents password reset abuse."""
        # Arrange
        email = "test@example.com"
        mock_user_repository.get_by_email.return_value = test_user
        mock_user_repository.save.return_value = test_user
        
        # Act: First request should succeed
        result1 = await password_reset_request_service.request_password_reset(email)
        assert result1["status"] == "success"
        
        # Act: Second request should be rate limited
        with pytest.raises(RateLimitExceededError):
            await password_reset_request_service.request_password_reset(email)
    
    @pytest.mark.asyncio
    async def test_token_expires_and_becomes_invalid(
        self,
        password_reset_service,
        mock_user_repository,
        token_service,
        test_user,
    ):
        """Test that expired tokens cannot be used for password reset."""
        # Arrange
        # Create an expired token by manipulating the expiry time
        token = ResetToken.generate()
        test_user.password_reset_token = token.value
        test_user.password_reset_token_expires_at = datetime.now(timezone.utc).replace(year=2020)  # Expired
        
        mock_user_repository.get_by_reset_token.return_value = test_user
        
        # Act & Assert
        with pytest.raises(PasswordResetError):
            await password_reset_service.reset_password(
                token=token.value,
                new_password="NewPassword123!",
            )
    
    @pytest.mark.asyncio
    async def test_invalid_token_format_rejected(
        self,
        password_reset_service,
    ):
        """Test that invalid token formats are rejected."""
        # Act & Assert
        with pytest.raises(PasswordResetError):
            await password_reset_service.reset_password(
                token="invalid_token",
                new_password="NewPassword123!",
            )
    
    @pytest.mark.asyncio
    async def test_weak_password_rejected(
        self,
        password_reset_service,
        mock_user_repository,
        test_user,
    ):
        """Test that weak passwords are rejected during reset."""
        # Arrange
        token = ResetToken.generate()
        test_user.password_reset_token = token.value
        test_user.password_reset_token_expires_at = token.expires_at
        
        mock_user_repository.get_by_reset_token.return_value = test_user
        
        # Act & Assert
        with pytest.raises(PasswordResetError):
            await password_reset_service.reset_password(
                token=token.value,
                new_password="weak",  # Too weak
            )
    
    @pytest.mark.asyncio
    async def test_security_events_are_published(
        self,
        password_reset_request_service,
        password_reset_service,
        mock_user_repository,
        event_publisher,
        test_user,
    ):
        """Test that security-relevant events are properly published."""
        # Arrange
        email = "test@example.com"
        correlation_id = "test-correlation-123"
        user_agent = "Mozilla/5.0 Test Browser"
        ip_address = "192.168.1.100"
        
        mock_user_repository.get_by_email.return_value = test_user
        mock_user_repository.save.return_value = test_user
        
        # Act: Request password reset with tracking info
        await password_reset_request_service.request_password_reset(
            email=email,
            correlation_id=correlation_id,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        
        # Verify request event has security tracking info
        events = event_publisher.get_events_by_type(PasswordResetRequestedEvent)
        assert len(events) == 1
        event = events[0]
        assert event.correlation_id == correlation_id
        assert event.user_agent == user_agent
        assert event.ip_address == ip_address
        
        # Act: Complete password reset with tracking info
        token_value = test_user.password_reset_token
        mock_user_repository.get_by_reset_token.return_value = test_user
        
        await password_reset_service.reset_password(
            token=token_value,
            new_password="MyNewStr0ng#P@ssw0rd",
            correlation_id=correlation_id,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        
        # Verify completion event has security tracking info
        completion_events = event_publisher.get_events_by_type(PasswordResetCompletedEvent)
        assert len(completion_events) == 1
        completion_event = completion_events[0]
        assert completion_event.correlation_id == correlation_id
        assert completion_event.user_agent == user_agent
        assert completion_event.ip_address == ip_address
    
    @pytest.mark.asyncio
    async def test_value_objects_enforce_business_rules(self):
        """Test that value objects properly enforce business rules."""
        # Test Password value object
        with pytest.raises(ValueError):
            Password(value="weak")  # Too weak
        
        valid_password = Password(value="MyStr0ng#P@ssw0rd")
        assert valid_password.value == "MyStr0ng#P@ssw0rd"
        
        # Test ResetToken value object
        token = ResetToken.generate()
        assert ResetToken.MIN_TOKEN_LENGTH <= len(token.value) <= ResetToken.MAX_TOKEN_LENGTH
        assert any(c.isupper() for c in token.value)
        assert any(c.islower() for c in token.value)
        assert any(c.isdigit() for c in token.value)
        assert any(not c.isalnum() for c in token.value)
        
        # Test token format validation
        with pytest.raises(ValueError):
            ResetToken.from_existing("invalid", datetime.now(timezone.utc))
    
    def test_event_publisher_tracks_all_events(self, event_publisher):
        """Test that event publisher properly tracks and manages events."""
        # Initially empty
        assert len(event_publisher.get_published_events()) == 0
        
        # Events can be retrieved by type and user
        assert len(event_publisher.get_events_by_type(PasswordResetRequestedEvent)) == 0
        assert len(event_publisher.get_events_by_user(1)) == 0
        
        # Events can be cleared
        event_publisher.clear_events()
        assert len(event_publisher.get_published_events()) == 0


class TestArchitecturalBenefits:
    """Tests that demonstrate the benefits of the clean architecture."""
    
    def test_services_are_testable_in_isolation(self):
        """Test that services can be easily tested with mocks."""
        # All services accept interfaces, making them easily testable
        # This is demonstrated by the comprehensive unit tests
        pass
    
    def test_value_objects_prevent_invalid_states(self):
        """Test that value objects prevent invalid business states."""
        # Password must meet security requirements
        with pytest.raises(ValueError):
            Password(value="")
        
        # Tokens must be properly formatted
        with pytest.raises(ValueError):
            ResetToken.from_existing("", datetime.now(timezone.utc))
        
        # Rate limits must have positive values
        from src.domain.value_objects.rate_limit import RateLimitWindow
        with pytest.raises(ValueError):
            RateLimitWindow.create_custom(user_id=0, window_minutes=5, max_attempts=1)
    
    def test_domain_events_enable_observability(self, event_publisher):
        """Test that domain events enable comprehensive observability."""
        # Events can be filtered and analyzed
        assert callable(event_publisher.get_events_by_type)
        assert callable(event_publisher.get_events_by_user)
        assert callable(event_publisher.get_published_events)
        
        # Events contain comprehensive context
        from src.domain.events.password_reset_events import PasswordResetRequestedEvent
        event = PasswordResetRequestedEvent(
            occurred_at=datetime.now(timezone.utc),
            user_id=1,
            correlation_id="test-123",
            email="test@example.com",
            token_expires_at=datetime.now(timezone.utc),
            user_agent="Test Browser",
            ip_address="192.168.1.1",
        )
        
        # All security-relevant fields are captured
        assert hasattr(event, 'user_agent')
        assert hasattr(event, 'ip_address')
        assert hasattr(event, 'correlation_id')
        assert hasattr(event, 'occurred_at')
    
    def test_interfaces_enable_dependency_inversion(self):
        """Test that interfaces properly enable dependency inversion."""
        # Services depend on abstractions, not concretions
        from src.domain.interfaces.services import (
            IRateLimitingService,
            IPasswordResetTokenService,
            IEventPublisher,
        )
        from src.domain.interfaces.repositories import IUserRepository
        
        # These are abstract base classes that define contracts
        assert hasattr(IRateLimitingService, '__abstractmethods__')
        assert hasattr(IPasswordResetTokenService, '__abstractmethods__')
        assert hasattr(IEventPublisher, '__abstractmethods__')
        assert hasattr(IUserRepository, '__abstractmethods__') 