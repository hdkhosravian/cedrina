"""Integration tests for the clean email confirmation architecture.

These tests verify that all components work together correctly,
demonstrating the benefits of the clean architecture approach.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock
import re

import pytest
from pydantic import EmailStr

from src.core.exceptions import EmailConfirmationError, RateLimitExceededError, AuthenticationError
from src.domain.entities.user import User, Role
from src.domain.events.email_confirmation_events import (
    EmailConfirmationRequestedEvent,
    EmailConfirmationCompletedEvent,
    EmailConfirmationFailedEvent,
)
from src.domain.services.email_confirmation.email_confirmation_service import (
    EmailConfirmationService,
)
from src.domain.services.authentication.user_registration_service import (
    UserRegistrationService,
)
from src.domain.services.authentication.user_authentication_service import (
    UserAuthenticationService,
)
from src.core.rate_limiting.password_reset_service import (
    RateLimitingService,
)
from src.domain.value_objects.email_confirmation_token import EmailConfirmationToken
from src.domain.value_objects.email import Email
from src.domain.value_objects.password import Password
from src.domain.value_objects.username import Username
from src.infrastructure.services.event_publisher import InMemoryEventPublisher
from src.infrastructure.services.email_confirmation_token_service import (
    EmailConfirmationTokenService,
)
from src.infrastructure.services.email_confirmation_email_service import (
    EmailConfirmationEmailService,
)


@pytest.fixture
def mock_user_repository():
    """Mock user repository for integration tests."""
    return AsyncMock()


@pytest.fixture
def mock_email_service():
    """Mock email service for integration tests."""
    mock = AsyncMock()
    mock.send_email_confirmation_email.return_value = True
    return mock


@pytest.fixture
def rate_limiting_service():
    """Real rate limiting service for integration tests."""
    return RateLimitingService()


@pytest.fixture
def token_service(rate_limiting_service):
    """Real token service for integration tests."""
    return EmailConfirmationTokenService(rate_limiting_service=rate_limiting_service)


@pytest.fixture
def email_service():
    """Real email service for integration tests."""
    return EmailConfirmationEmailService(test_mode=True)


@pytest.fixture
def event_publisher():
    """In-memory event publisher for integration tests."""
    return InMemoryEventPublisher()


@pytest.fixture
def email_confirmation_service(
    mock_user_repository,
    token_service,
    email_service,
    event_publisher,
):
    """Email confirmation service with real components."""
    return EmailConfirmationService(
        user_repository=mock_user_repository,
        token_service=token_service,
        email_service=email_service,
        event_publisher=event_publisher,
    )


@pytest.fixture
def user_registration_service(
    mock_user_repository,
    event_publisher,
    email_confirmation_service,
):
    """User registration service with real components."""
    return UserRegistrationService(
        user_repository=mock_user_repository,
        event_publisher=event_publisher,
        email_confirmation_service=email_confirmation_service,
    )


@pytest.fixture
def user_authentication_service(
    mock_user_repository,
    event_publisher,
):
    """User authentication service with real components."""
    return UserAuthenticationService(
        user_repository=mock_user_repository,
        event_publisher=event_publisher,
    )


@pytest.fixture
def test_user():
    """Test user fixture."""
    return User(
        id=1,
        username="testuser",
        email="test@example.com",
        hashed_password="$2b$12$oldhash",
        role=Role.USER,
        is_active=False,
        email_confirmed=False,
        email_confirmation_token=None,
    )


@pytest.fixture
def confirmed_user():
    """Confirmed user fixture."""
    return User(
        id=2,
        username="confirmeduser",
        email="confirmed@example.com",
        hashed_password="$2b$12$oldhash",
        role=Role.USER,
        is_active=True,
        email_confirmed=True,
        email_confirmed_at=datetime.now(timezone.utc),
        email_confirmation_token=None,
    )


class TestEmailConfirmationIntegration:
    """Integration tests for the complete email confirmation workflow."""
    
    @pytest.mark.asyncio
    async def test_complete_email_confirmation_workflow(
        self,
        email_confirmation_service,
        user_registration_service,
        user_authentication_service,
        mock_user_repository,
        event_publisher,
        test_user,
    ):
        """Test the complete end-to-end email confirmation workflow."""
        # Arrange
        email = "test@example.com"
        password = "StrongP@ssw0rd!"
        
        # Mock repository responses
        mock_user_repository.get_by_email.return_value = test_user
        mock_user_repository.save.return_value = test_user
        mock_user_repository.get_by_confirmation_token.return_value = test_user
        
        # Step 1: Register user with email confirmation enabled
        username = Username(value="testuser")
        email_obj = Email(value=email)
        password_obj = Password(value=password)
        
        registered_user = await user_registration_service.register_user(
            username=username,
            email=email_obj,
            password=password_obj,
        )
        
        # Verify user is inactive and needs confirmation
        assert registered_user.is_active is False
        assert registered_user.email_confirmed is False
        assert registered_user.email_confirmation_token is not None
        
        # Verify domain event was published
        events = event_publisher.get_published_events()
        request_events = [e for e in events if isinstance(e, EmailConfirmationRequestedEvent)]
        assert len(request_events) == 1
        assert request_events[0].email == email
        
        # Step 2: Extract token from user (simulate email link click)
        token_value = registered_user.email_confirmation_token
        assert token_value is not None
        assert EmailConfirmationToken.MIN_TOKEN_LENGTH <= len(token_value) <= EmailConfirmationToken.MAX_TOKEN_LENGTH
        
        # Step 3: Confirm email using token
        confirmed_user = await email_confirmation_service.confirm_email(
            token=token_value,
        )
        
        # Verify confirmation was successful
        assert confirmed_user.is_active is True
        assert confirmed_user.email_confirmed is True
        assert confirmed_user.email_confirmation_token is None
        assert confirmed_user.email_confirmed_at is not None
        
        # Verify completion event was published
        all_events = event_publisher.get_published_events()
        completion_events = [e for e in all_events if isinstance(e, EmailConfirmationCompletedEvent)]
        assert len(completion_events) == 1
        assert completion_events[0].email == email
        
        # Step 4: Verify user can now authenticate
        auth_result = await user_authentication_service.authenticate_user(
            email=email,
            password=password,
        )
        
        assert auth_result["status"] == "success"
        assert auth_result["user"].id == confirmed_user.id
    
    @pytest.mark.asyncio
    async def test_login_blocked_without_email_confirmation(
        self,
        user_authentication_service,
        mock_user_repository,
        test_user,
    ):
        """Test that login is blocked for unconfirmed users."""
        # Arrange
        email = "test@example.com"
        password = "StrongP@ssw0rd!"
        
        # Mock unconfirmed user
        test_user.is_active = False
        test_user.email_confirmed = False
        mock_user_repository.get_by_email.return_value = test_user
        
        # Act & Assert
        with pytest.raises(AuthenticationError) as exc_info:
            await user_authentication_service.authenticate_user(
                username=Username(value=email),  # Use email as username
                password=Password(value=password),
            )
        
        assert "email confirmation" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_rate_limiting_prevents_confirmation_abuse(
        self,
        email_confirmation_service,
        mock_user_repository,
        test_user,
    ):
        """Test that rate limiting prevents email confirmation abuse."""
        # Arrange
        mock_user_repository.get_by_email.return_value = test_user
        mock_user_repository.save.return_value = test_user
        
        # Act: First confirmation email should succeed
        result1 = await email_confirmation_service.send_confirmation_email(test_user)
        assert result1 is True
        
        # Act: Second confirmation email should be rate limited
        with pytest.raises(RateLimitExceededError):
            await email_confirmation_service.send_confirmation_email(test_user)
    
    @pytest.mark.asyncio
    async def test_invalid_token_rejected(
        self,
        email_confirmation_service,
    ):
        """Test that invalid tokens are rejected."""
        # Arrange
        invalid_token = "invalid_token_format"
        
        # Act & Assert
        with pytest.raises(EmailConfirmationError):
            await email_confirmation_service.confirm_email(token=invalid_token)
    
    @pytest.mark.asyncio
    async def test_expired_token_rejected(
        self,
        email_confirmation_service,
        mock_user_repository,
        test_user,
    ):
        """Test that expired tokens cannot be used."""
        # Arrange
        # Create an expired token by manipulating the expiry time
        token = EmailConfirmationToken.generate()
        test_user.email_confirmation_token = token.value
        test_user.email_confirmation_token_expires_at = datetime.now(timezone.utc).replace(year=2020)  # Expired
        
        mock_user_repository.get_by_confirmation_token.return_value = test_user
        
        # Act & Assert
        with pytest.raises(EmailConfirmationError):
            await email_confirmation_service.confirm_email(token=token.value)
    
    @pytest.mark.asyncio
    async def test_resend_confirmation_email_workflow(
        self,
        email_confirmation_service,
        mock_user_repository,
        event_publisher,
        test_user,
    ):
        """Test resend confirmation email workflow."""
        # Arrange
        email = "test@example.com"
        mock_user_repository.get_by_email.return_value = test_user
        mock_user_repository.save.return_value = test_user
        
        # Act: Resend confirmation email
        result = await email_confirmation_service.resend_confirmation_email(email)
        
        # Assert
        assert result is True
        
        # Verify new token was generated
        save_calls = mock_user_repository.save.call_args_list
        assert len(save_calls) >= 1
        
        # Verify resend event was published
        events = event_publisher.get_published_events()
        request_events = [e for e in events if isinstance(e, EmailConfirmationRequestedEvent)]
        assert len(request_events) == 1
        assert request_events[0].confirmation_method == "resend"
    
    @pytest.mark.asyncio
    async def test_resend_confirmation_for_already_confirmed_user(
        self,
        email_confirmation_service,
        mock_user_repository,
        confirmed_user,
    ):
        """Test resend confirmation for already confirmed user."""
        # Arrange
        email = "confirmed@example.com"
        mock_user_repository.get_by_email.return_value = confirmed_user
        
        # Act: Resend confirmation email for confirmed user
        result = await email_confirmation_service.resend_confirmation_email(email)
        
        # Assert: Should return success but not send email
        assert result is True
        
        # Verify no save was called (user already confirmed)
        mock_user_repository.save.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_resend_confirmation_for_nonexistent_user(
        self,
        email_confirmation_service,
        mock_user_repository,
    ):
        """Test resend confirmation for nonexistent user."""
        # Arrange
        email = "nonexistent@example.com"
        mock_user_repository.get_by_email.return_value = None
        
        # Act & Assert
        from src.core.exceptions import UserNotFoundError
        with pytest.raises(UserNotFoundError):
            await email_confirmation_service.resend_confirmation_email(email)
    
    @pytest.mark.asyncio
    async def test_confirmation_token_invalidation_after_use(
        self,
        email_confirmation_service,
        mock_user_repository,
        test_user,
    ):
        """Test that confirmation token is invalidated after use."""
        # Arrange
        token_value = "valid_token_123"
        test_user.email_confirmation_token = token_value
        test_user.email_confirmation_token_expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        
        mock_user_repository.get_by_confirmation_token.return_value = test_user
        mock_user_repository.save.return_value = test_user
        
        # Act: Confirm email
        confirmed_user = await email_confirmation_service.confirm_email(token_value)
        
        # Assert: Token should be cleared
        assert confirmed_user.email_confirmation_token is None
        assert confirmed_user.email_confirmed_at is not None
        
        # Act: Try to use the same token again
        mock_user_repository.get_by_confirmation_token.return_value = None
        
        with pytest.raises(EmailConfirmationError):
            await email_confirmation_service.confirm_email(token_value)
    
    @pytest.mark.asyncio
    async def test_security_events_are_published(
        self,
        email_confirmation_service,
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
        
        # Act: Send confirmation email with tracking info
        await email_confirmation_service.send_confirmation_email(
            user=test_user,
            language="en"
        )
        
        # Verify request event was published
        events = event_publisher.get_events_by_type(EmailConfirmationRequestedEvent)
        assert len(events) == 1
        event = events[0]
        assert event.email == email
        
        # Act: Confirm email with tracking info
        token_value = test_user.email_confirmation_token
        mock_user_repository.get_by_confirmation_token.return_value = test_user
        
        await email_confirmation_service.confirm_email(
            token=token_value,
            language="en"
        )
        
        # Verify completion event was published
        completion_events = event_publisher.get_events_by_type(EmailConfirmationCompletedEvent)
        assert len(completion_events) == 1
        completion_event = completion_events[0]
        assert completion_event.email == email
    
    @pytest.mark.asyncio
    async def test_failed_confirmation_events_are_published(
        self,
        email_confirmation_service,
        mock_user_repository,
        event_publisher,
    ):
        """Test that failed confirmation events are published."""
        # Arrange
        invalid_token = "invalid_token"
        mock_user_repository.get_by_confirmation_token.return_value = None
        
        # Act & Assert
        with pytest.raises(EmailConfirmationError):
            await email_confirmation_service.confirm_email(token=invalid_token)
        
        # Verify failure event was published
        failure_events = event_publisher.get_events_by_type(EmailConfirmationFailedEvent)
        assert len(failure_events) == 1
        failure_event = failure_events[0]
        assert failure_event.failure_reason == "token_validation_failed"
    
    @pytest.mark.asyncio
    async def test_value_objects_enforce_business_rules(self):
        """Test that value objects properly enforce business rules."""
        # Test EmailConfirmationToken value object
        token = EmailConfirmationToken.generate()
        assert EmailConfirmationToken.MIN_TOKEN_LENGTH <= len(token.value) <= EmailConfirmationToken.MAX_TOKEN_LENGTH
        
        # Test token format validation
        with pytest.raises(ValueError):
            EmailConfirmationToken.from_existing("invalid", datetime.now(timezone.utc))
        
        # Test Email value object
        valid_email = Email(value="test@example.com")
        assert valid_email.value == "test@example.com"
        
        with pytest.raises(ValueError):
            Email(value="invalid-email")
        
        # Test Password value object
        valid_password = Password(value="StrongP@ssw0rd!")
        assert valid_password.value == "StrongP@ssw0rd!"
        
        with pytest.raises(ValueError):
            Password(value="weak")
    
    def test_event_publisher_tracks_all_events(self, event_publisher):
        """Test that event publisher properly tracks and manages events."""
        # Initially empty
        assert len(event_publisher.get_published_events()) == 0
        
        # Events can be retrieved by type and user
        assert len(event_publisher.get_events_by_type(EmailConfirmationRequestedEvent)) == 0
        assert len(event_publisher.get_events_by_user(1)) == 0
        
        # Events can be cleared
        event_publisher.clear_events()
        assert len(event_publisher.get_published_events()) == 0
    
    @pytest.mark.asyncio
    async def test_multilingual_support(
        self,
        email_confirmation_service,
        mock_user_repository,
        test_user,
    ):
        """Test multilingual support for email confirmation."""
        # Arrange
        languages = ["en", "es", "ar", "fa"]
        mock_user_repository.get_by_email.return_value = test_user
        mock_user_repository.save.return_value = test_user
        
        for language in languages:
            # Act: Send confirmation email in different language
            result = await email_confirmation_service.send_confirmation_email(
                user=test_user,
                language=language
            )
            
            # Assert: Should succeed for all languages
            assert result is True
    
    @pytest.mark.asyncio
    async def test_user_registration_with_email_confirmation_disabled(
        self,
        user_registration_service,
        mock_user_repository,
        event_publisher,
    ):
        """Test user registration when email confirmation is disabled."""
        # Arrange
        username = Username(value="testuser")
        email_obj = Email(value="test@example.com")
        password_obj = Password(value="StrongP@ssw0rd!")
        
        # Mock settings to disable email confirmation
        with patch("src.core.config.settings.settings.EMAIL_CONFIRMATION_ENABLED", False):
            # Act: Register user
            registered_user = await user_registration_service.register_user(
                username=username,
                email=email_obj,
                password=password_obj,
            )
            
            # Assert: User should be active immediately
            assert registered_user.is_active is True
            assert registered_user.email_confirmed is True
            
            # Verify no confirmation events were published
            events = event_publisher.get_published_events()
            confirmation_events = [e for e in events if isinstance(e, EmailConfirmationRequestedEvent)]
            assert len(confirmation_events) == 0


# Import for patch decorator
from unittest.mock import patch
from datetime import timedelta 