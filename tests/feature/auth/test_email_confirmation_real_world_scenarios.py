"""Real-world scenario tests for email confirmation feature.

This module contains comprehensive tests that simulate real-world user scenarios,
security threats, and production conditions for the email confirmation feature.
These tests go beyond unit testing to validate end-to-end workflows and ensure
the system behaves correctly under realistic conditions.

Test Categories:
- User Registration and Email Confirmation Flow
- Security Scenarios (Rate Limiting, Token Validation)
- Error Handling and Edge Cases
- Multi-language Support
- Production-like Conditions
- Integration with Other Features
"""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
import os

from src.main import app
from src.domain.entities.user import User, Role
from src.domain.value_objects.reset_token import ResetToken
from src.core.exceptions import AuthenticationError, EmailServiceError
from src.infrastructure.services.email.unified_email_service import UnifiedEmailService
from src.core.rate_limiting.email_rate_limiter import EmailRateLimiter
from src.core.config.settings import settings


class TestEmailConfirmationRealWorldScenarios:
    """Real-world scenario tests for email confirmation feature."""

    @pytest.fixture
    def client(self):
        """Test client fixture with correct router inclusion."""
        from fastapi import FastAPI
        from src.adapters.api.v1.auth import router as auth_router
        os.environ["APP_ENV"] = "test"
        app = FastAPI()
        app.include_router(auth_router)
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
            email_confirmation_token=None,
        )

    @pytest.fixture
    def confirmed_user(self):
        """Confirmed user fixture."""
        return User(
            id=2,
            username="confirmeduser",
            email="confirmed@example.com",
            hashed_password="hashed_password",
            role=Role.USER,
            is_active=True,
            email_confirmed=True,
            email_confirmed_at=datetime.now(timezone.utc),
            email_confirmation_token=None,
        )

    @pytest.fixture
    def mock_email_service(self):
        """Mock unified email service."""
        mock = AsyncMock(spec=UnifiedEmailService)
        mock.send_email_confirmation_email.return_value = True
        mock.is_rate_limited.return_value = False
        mock.record_email_attempt.return_value = None
        mock.is_test_mode.return_value = True
        return mock

    @pytest.fixture
    def mock_rate_limiter(self):
        """Mock email rate limiter."""
        mock = AsyncMock(spec=EmailRateLimiter)
        mock.is_rate_limited.return_value = False
        mock.record_attempt.return_value = None
        return mock

    # ============================================================================
    # User Registration and Email Confirmation Flow Tests
    # ============================================================================

    @pytest.mark.asyncio
    async def test_complete_user_registration_and_confirmation_flow(
        self, client, mock_email_service, mock_rate_limiter
    ):
        """Test complete user registration and email confirmation workflow.
        
        This test simulates the real-world scenario where a user:
        1. Registers for an account
        2. Receives confirmation email
        3. Clicks confirmation link
        4. Gets activated and can log in
        """
        # Arrange
        with patch("src.infrastructure.dependency_injection.auth_dependencies.get_unified_email_service", return_value=mock_email_service):
            with patch("src.core.rate_limiting.email_rate_limiter.EmailRateLimiter", return_value=mock_rate_limiter):
                
                # Step 1: User registration with email confirmation enabled
                registration_data = {
                    "username": "newuser",
                    "email": "newuser@example.com",
                    "password": "SecurePass123!"
                }
                
                # Mock registration service to return inactive user
                mock_user = User(
                    id=3,
                    username="newuser",
                    email="newuser@example.com",
                    hashed_password="hashed_password",
                    role=Role.USER,
                    is_active=False,  # Should be inactive when email confirmation is enabled
                    email_confirmed=False,
                    email_confirmation_token="test_token_123",
                )
                
                with patch("src.domain.services.authentication.user_registration_service.UserRegistrationService.register_user", return_value=mock_user):
                    # Act: Register user
                    response = client.post("/auth/register", json=registration_data)
                    
                    # Assert: Registration successful but user inactive
                    assert response.status_code == 201
                    data = response.json()
                    assert data["user"]["is_active"] is False
                    assert data["user"]["email_confirmed"] is False
                    
                    # Verify email confirmation was sent
                    mock_email_service.send_email_confirmation_email.assert_called_once()
                
                # Step 2: Mock email confirmation service
                with patch("src.domain.services.email_confirmation.email_confirmation_service.EmailConfirmationService.confirm_email", return_value=mock_user):
                    # Act: Confirm email
                    confirm_data = {"token": "test_token_123"}
                    response = client.post("/auth/confirm-email/", json=confirm_data)
                    
                    # Assert: Email confirmation successful
                    assert response.status_code == 200
                    data = response.json()
                    assert data["message"] == "Email confirmed successfully"
                    assert data["user"]["email_confirmed"] is True
                    assert data["user"]["is_active"] is True

    @pytest.mark.asyncio
    async def test_user_registration_without_email_confirmation(
        self, client, mock_email_service
    ):
        """Test user registration when email confirmation is disabled.
        
        This test simulates the scenario where email confirmation is disabled
        and users are automatically activated upon registration.
        """
        # Arrange
        with patch("src.infrastructure.dependency_injection.auth_dependencies.get_unified_email_service", return_value=mock_email_service):
            with patch("src.core.config.settings.settings.EMAIL_CONFIRMATION_ENABLED", False):
                
                registration_data = {
                    "username": "autoactiveuser",
                    "email": "autoactive@example.com",
                    "password": "SecurePass123!"
                }
                
                # Mock registration service to return active user
                mock_user = User(
                    id=4,
                    username="autoactiveuser",
                    email="autoactive@example.com",
                    hashed_password="hashed_password",
                    role=Role.USER,
                    is_active=True,  # Should be active when email confirmation is disabled
                    email_confirmed=False,
                )
                
                with patch("src.domain.services.authentication.user_registration_service.UserRegistrationService.register_user", return_value=mock_user):
                    # Act: Register user
                    response = client.post("/auth/register", json=registration_data)
                    
                    # Assert: Registration successful and user active
                    assert response.status_code == 201
                    data = response.json()
                    assert data["user"]["is_active"] is True
                    
                    # Verify no email confirmation was sent
                    mock_email_service.send_email_confirmation_email.assert_not_called()

    # ============================================================================
    # Security Scenario Tests
    # ============================================================================

    @pytest.mark.asyncio
    async def test_rate_limiting_for_email_confirmation(
        self, client, mock_email_service, mock_rate_limiter
    ):
        """Test rate limiting prevents email confirmation abuse.
        
        This test simulates a malicious user trying to spam email confirmations
        and verifies that rate limiting prevents abuse.
        """
        # Arrange
        mock_rate_limiter.is_rate_limited.return_value = True  # User is rate limited
        
        with patch("src.infrastructure.dependency_injection.auth_dependencies.get_unified_email_service", return_value=mock_email_service):
            with patch("src.core.rate_limiting.email_rate_limiter.EmailRateLimiter", return_value=mock_rate_limiter):
                
                # Mock user repository to return existing user
                mock_user = User(
                    id=5,
                    username="rate_limited_user",
                    email="rate_limited@example.com",
                    hashed_password="hashed_password",
                    role=Role.USER,
                    is_active=False,
                    email_confirmed=False,
                )
                
                with patch("src.infrastructure.repositories.user_repository.UserRepository.get_by_email", return_value=mock_user):
                    # Act: Try to resend confirmation email
                    resend_data = {"email": "rate_limited@example.com"}
                    response = client.post("/auth/confirm-email/resend", json=resend_data)
                    
                    # Assert: Should return success to prevent information disclosure
                    assert response.status_code == 200
                    assert "receive a confirmation email" in response.json()["message"]
                    
                    # Verify no email was actually sent due to rate limiting
                    mock_email_service.send_email_confirmation_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_invalid_token_handling(
        self, client, mock_email_service
    ):
        """Test handling of invalid confirmation tokens.
        
        This test simulates various invalid token scenarios and verifies
        proper error handling without information disclosure.
        """
        # Arrange
        with patch("src.infrastructure.dependency_injection.auth_dependencies.get_unified_email_service", return_value=mock_email_service):
            
            # Test cases for invalid tokens
            invalid_tokens = [
                "",  # Empty token
                "invalid_token",  # Invalid format
                "expired_token_123",  # Expired token
                "a" * 100,  # Too long token
                "token with spaces",  # Token with spaces
                "token@with@special@chars",  # Token with special chars
            ]
            
            for token in invalid_tokens:
                # Mock service to raise authentication error
                with patch("src.domain.services.email_confirmation.email_confirmation_service.EmailConfirmationService.confirm_email", side_effect=AuthenticationError("Invalid or expired email confirmation token")):
                    # Act: Try to confirm with invalid token
                    confirm_data = {"token": token}
                    response = client.post("/auth/confirm-email/", json=confirm_data)
                    
                    # Assert: Proper error response
                    assert response.status_code == 400
                    assert "Invalid or expired email confirmation token" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_email_enumeration_protection(
        self, client, mock_email_service
    ):
        """Test protection against email enumeration attacks.
        
        This test verifies that the system doesn't reveal whether an email
        address exists in the system, preventing enumeration attacks.
        """
        # Arrange
        with patch("src.infrastructure.dependency_injection.auth_dependencies.get_unified_email_service", return_value=mock_email_service):
            
            # Test with non-existent email
            with patch("src.infrastructure.repositories.user_repository.UserRepository.get_by_email", return_value=None):
                # Act: Try to resend confirmation for non-existent email
                resend_data = {"email": "nonexistent@example.com"}
                response = client.post("/auth/confirm-email/resend", json=resend_data)
                
                # Assert: Should return success to prevent enumeration
                assert response.status_code == 200
                assert "receive a confirmation email" in response.json()["message"]
                
                # Verify no email was sent
                mock_email_service.send_email_confirmation_email.assert_not_called()
            
            # Test with existing but unconfirmed email
            mock_user = User(
                id=6,
                username="existinguser",
                email="existing@example.com",
                hashed_password="hashed_password",
                role=Role.USER,
                is_active=False,
                email_confirmed=False,
            )
            
            with patch("src.infrastructure.repositories.user_repository.UserRepository.get_by_email", return_value=mock_user):
                # Act: Try to resend confirmation for existing email
                resend_data = {"email": "existing@example.com"}
                response = client.post("/auth/confirm-email/resend", json=resend_data)
                
                # Assert: Should return success
                assert response.status_code == 200
                assert "receive a confirmation email" in response.json()["message"]

    # ============================================================================
    # Multi-language Support Tests
    # ============================================================================

    @pytest.mark.asyncio
    async def test_email_confirmation_multilingual_support(
        self, client, mock_email_service
    ):
        """Test email confirmation with different languages.
        
        This test verifies that email confirmation works correctly
        with different language preferences.
        """
        # Arrange
        with patch("src.infrastructure.dependency_injection.auth_dependencies.get_unified_email_service", return_value=mock_email_service):
            
            # Test different languages
            languages = ["en", "es", "fa", "ar"]
            
            for language in languages:
                # Mock registration service
                mock_user = User(
                    id=7,
                    username=f"user_{language}",
                    email=f"user_{language}@example.com",
                    hashed_password="hashed_password",
                    role=Role.USER,
                    is_active=False,
                    email_confirmed=False,
                    email_confirmation_token="test_token_123",
                )
                
                with patch("src.domain.services.authentication.user_registration_service.UserRegistrationService.register_user", return_value=mock_user):
                    # Act: Register user with specific language
                    registration_data = {
                        "username": f"user_{language}",
                        "email": f"user_{language}@example.com",
                        "password": "SecurePass123!"
                    }
                    
                    headers = {"Accept-Language": language}
                    response = client.post("/auth/register", json=registration_data, headers=headers)
                    
                    # Assert: Registration successful
                    assert response.status_code == 201
                    
                    # Verify email was sent with correct language
                    mock_email_service.send_email_confirmation_email.assert_called_with(
                        user=mock_user,
                        confirmation_token="test_token_123",
                        language=language
                    )

    # ============================================================================
    # Error Handling and Edge Cases Tests
    # ============================================================================

    @pytest.mark.asyncio
    async def test_email_service_failure_handling(
        self, client, mock_email_service
    ):
        """Test handling of email service failures.
        
        This test simulates email service failures and verifies
        proper error handling and user experience.
        """
        # Arrange
        mock_email_service.send_email_confirmation_email.side_effect = EmailServiceError("SMTP connection failed")
        
        with patch("src.infrastructure.dependency_injection.auth_dependencies.get_unified_email_service", return_value=mock_email_service):
            
            # Mock registration service
            mock_user = User(
                id=8,
                username="email_failure_user",
                email="email_failure@example.com",
                hashed_password="hashed_password",
                role=Role.USER,
                is_active=False,
                email_confirmed=False,
            )
            
            with patch("src.domain.services.authentication.user_registration_service.UserRegistrationService.register_user", return_value=mock_user):
                # Act: Register user
                registration_data = {
                    "username": "email_failure_user",
                    "email": "email_failure@example.com",
                    "password": "SecurePass123!"
                }
                
                response = client.post("/auth/register", json=registration_data)
                
                # Assert: Registration should still succeed even if email fails
                assert response.status_code == 201
                data = response.json()
                assert data["user"]["is_active"] is False  # User should remain inactive

    @pytest.mark.asyncio
    async def test_concurrent_confirmation_attempts(
        self, client, mock_email_service
    ):
        """Test handling of concurrent email confirmation attempts.
        
        This test simulates multiple users trying to confirm emails
        simultaneously and verifies proper handling.
        """
        # Arrange
        with patch("src.infrastructure.dependency_injection.auth_dependencies.get_unified_email_service", return_value=mock_email_service):
            
            # Create multiple users with same token
            users = []
            for i in range(3):
                user = User(
                    id=9 + i,
                    username=f"concurrent_user_{i}",
                    email=f"concurrent_{i}@example.com",
                    hashed_password="hashed_password",
                    role=Role.USER,
                    is_active=False,
                    email_confirmed=False,
                    email_confirmation_token="shared_token_123",
                )
                users.append(user)
            
            # Mock service to handle concurrent requests
            async def mock_confirm_email(token, correlation_id):
                # Simulate race condition - only first user should succeed
                if token == "shared_token_123":
                    return users[0]  # Return first user
                raise AuthenticationError("Invalid token")
            
            with patch("src.domain.services.email_confirmation.email_confirmation_service.EmailConfirmationService.confirm_email", side_effect=mock_confirm_email):
                # Act: Multiple concurrent confirmation attempts
                confirm_data = {"token": "shared_token_123"}
                
                # Simulate concurrent requests
                responses = []
                for _ in range(3):
                    response = client.post("/auth/confirm-email/", json=confirm_data)
                    responses.append(response)
                
                # Assert: Only one should succeed, others should fail
                success_count = sum(1 for r in responses if r.status_code == 200)
                assert success_count == 1

    # ============================================================================
    # Production-like Condition Tests
    # ============================================================================

    @pytest.mark.asyncio
    async def test_email_confirmation_with_large_user_load(
        self, client, mock_email_service
    ):
        """Test email confirmation under high user load.
        
        This test simulates a high-traffic scenario with many users
        registering and confirming emails simultaneously.
        """
        # Arrange
        with patch("src.infrastructure.dependency_injection.auth_dependencies.get_unified_email_service", return_value=mock_email_service):
            
            # Simulate 100 concurrent registrations
            registration_tasks = []
            
            for i in range(100):
                user_data = {
                    "username": f"loadtest_user_{i}",
                    "email": f"loadtest_{i}@example.com",
                    "password": "SecurePass123!"
                }
                
                mock_user = User(
                    id=100 + i,
                    username=f"loadtest_user_{i}",
                    email=f"loadtest_{i}@example.com",
                    hashed_password="hashed_password",
                    role=Role.USER,
                    is_active=False,
                    email_confirmed=False,
                    email_confirmation_token=f"token_{i}",
                )
                
                with patch("src.domain.services.authentication.user_registration_service.UserRegistrationService.register_user", return_value=mock_user):
                    response = client.post("/auth/register", json=user_data)
                    registration_tasks.append(response)
            
            # Assert: All registrations should succeed
            success_count = sum(1 for r in registration_tasks if r.status_code == 201)
            assert success_count == 100
            
            # Verify emails were sent for all users
            assert mock_email_service.send_email_confirmation_email.call_count == 100

    @pytest.mark.asyncio
    async def test_email_confirmation_with_network_latency(
        self, client, mock_email_service
    ):
        """Test email confirmation with simulated network latency.
        
        This test simulates real-world network conditions and verifies
        the system handles latency gracefully.
        """
        # Arrange
        async def delayed_email_send(*args, **kwargs):
            await asyncio.sleep(0.1)  # Simulate 100ms latency
            return True
        
        mock_email_service.send_email_confirmation_email.side_effect = delayed_email_send
        
        with patch("src.infrastructure.dependency_injection.auth_dependencies.get_unified_email_service", return_value=mock_email_service):
            
            mock_user = User(
                id=201,
                username="latency_user",
                email="latency@example.com",
                hashed_password="hashed_password",
                role=Role.USER,
                is_active=False,
                email_confirmed=False,
                email_confirmation_token="latency_token_123",
            )
            
            with patch("src.domain.services.authentication.user_registration_service.UserRegistrationService.register_user", return_value=mock_user):
                # Act: Register user with latency
                registration_data = {
                    "username": "latency_user",
                    "email": "latency@example.com",
                    "password": "SecurePass123!"
                }
                
                response = client.post("/auth/register", json=registration_data)
                
                # Assert: Registration should succeed despite latency
                assert response.status_code == 201

    # ============================================================================
    # Integration Tests
    # ============================================================================

    @pytest.mark.asyncio
    async def test_email_confirmation_integration_with_login(
        self, client, mock_email_service
    ):
        """Test integration between email confirmation and login.
        
        This test verifies that users cannot log in until their email
        is confirmed when the feature is enabled.
        """
        # Arrange
        with patch("src.infrastructure.dependency_injection.auth_dependencies.get_unified_email_service", return_value=mock_email_service):
            
            # Mock unconfirmed user
            unconfirmed_user = User(
                id=202,
                username="unconfirmed_user",
                email="unconfirmed@example.com",
                hashed_password="hashed_password",
                role=Role.USER,
                is_active=False,
                email_confirmed=False,
            )
            
            # Mock confirmed user
            confirmed_user = User(
                id=203,
                username="confirmed_user",
                email="confirmed@example.com",
                hashed_password="hashed_password",
                role=Role.USER,
                is_active=True,
                email_confirmed=True,
            )
            
            # Test login attempt for unconfirmed user
            with patch("src.domain.services.authentication.user_authentication_security_service.UserAuthenticationSecurityService.authenticate_user", side_effect=AuthenticationError("Please confirm your email address before logging in")):
                login_data = {
                    "username": "unconfirmed_user",
                    "password": "SecurePass123!"
                }
                
                response = client.post("/auth/login", json=login_data)
                
                # Assert: Login should be blocked
                assert response.status_code == 400
                assert "confirm your email" in response.json()["detail"]
            
            # Test login attempt for confirmed user
            with patch("src.domain.services.authentication.user_authentication_security_service.UserAuthenticationSecurityService.authenticate_user", return_value=confirmed_user):
                with patch("src.infrastructure.services.authentication.token.TokenService.create_token_pair", return_value={"access_token": "token", "refresh_token": "refresh"}):
                    login_data = {
                        "username": "confirmed_user",
                        "password": "SecurePass123!"
                    }
                    
                    response = client.post("/auth/login", json=login_data)
                    
                    # Assert: Login should succeed
                    assert response.status_code == 200
                    assert "access_token" in response.json()["tokens"]

    @pytest.mark.asyncio
    async def test_email_confirmation_with_password_reset_integration(
        self, client, mock_email_service
    ):
        """Test integration between email confirmation and password reset.
        
        This test verifies that password reset functionality works correctly
        for both confirmed and unconfirmed users.
        """
        # Arrange
        with patch("src.infrastructure.dependency_injection.auth_dependencies.get_unified_email_service", return_value=mock_email_service):
            
            # Mock user with email confirmation token
            user_with_confirmation = User(
                id=204,
                username="user_with_confirmation",
                email="user_with_confirmation@example.com",
                hashed_password="hashed_password",
                role=Role.USER,
                is_active=False,
                email_confirmed=False,
                email_confirmation_token="confirmation_token_123",
            )
            
            # Test password reset for user with pending confirmation
            with patch("src.infrastructure.repositories.user_repository.UserRepository.get_by_email", return_value=user_with_confirmation):
                reset_data = {"email": "user_with_confirmation@example.com"}
                
                response = client.post("/auth/forgot-password", json=reset_data)
                
                # Assert: Password reset should work regardless of email confirmation status
                assert response.status_code == 200
                assert "password reset email" in response.json()["message"]
                
                # Verify password reset email was sent
                mock_email_service.send_password_reset_email.assert_called_once() 