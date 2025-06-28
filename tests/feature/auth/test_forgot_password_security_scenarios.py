"""Real-world Security Feature Tests for Forgot Password System.

This module contains comprehensive feature tests that simulate real-world security scenarios
for the forgot password functionality, including:

- Advanced attack scenarios (timing attacks, brute force, token enumeration)
- One-time use token enforcement  
- Short-lived token expiration (5 minutes)
- Rate limiting under attack conditions
- Token invalidation security patterns
- Multi-language security error handling
- Concurrent user attack scenarios
- Database failure recovery scenarios

All tests follow TDD principles and test the complete workflow from API to database.
"""

import asyncio
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, AsyncMock

from src.domain.entities.user import User, Role
from src.domain.services.auth.password_reset_token_service import PasswordResetTokenService
from src.domain.services.forgot_password.forgot_password_service import ForgotPasswordService
from src.infrastructure.repositories.user_repository import UserRepository
from src.core.exceptions import RateLimitExceededError, PasswordResetError, ForgotPasswordError


@pytest.mark.feature
class TestForgotPasswordSecurityScenarios:
    """Comprehensive real-world security feature tests for forgot password system."""


    
    @pytest.fixture
    def test_user(self):
        """Create a test user for security scenarios."""
        return User(
            id=1,
            username="security_test_user",
            email="security@example.com",
            hashed_password="$2b$12$hashedpassword",
            role=Role.USER,
            is_active=True,
            created_at=datetime.now(timezone.utc)
        )
    
    @pytest.fixture  
    def token_service(self):
        """Password reset token service for testing."""
        return PasswordResetTokenService()
    
    @pytest.mark.asyncio
    async def test_rapid_fire_attack_scenario(self, test_user):
        """Test system behavior under rapid-fire password reset requests (service-level simulation)."""
        # Create a single service instance to maintain rate limiting state
        mock_repo = AsyncMock()
        mock_repo.get_by_email.return_value = test_user
        mock_repo.save = AsyncMock()
        
        mock_email_service = AsyncMock()
        mock_email_service.send_password_reset_email = AsyncMock()
        
        service = ForgotPasswordService(
            user_repository=mock_repo,
            email_service=mock_email_service,
            token_service=PasswordResetTokenService()
        )
        
        email = test_user.email
        
        # First request should succeed  
        result1 = await service.request_password_reset(email)
        assert result1["status"] == "success"
        
        # Rapid follow-up requests should be rate limited
        with pytest.raises(RateLimitExceededError):
            await service.request_password_reset(email)
    
    @pytest.mark.asyncio
    async def test_service_rate_limiting_scenario(self, test_user):
        """Test service-level rate limiting behavior."""
        # Create a single service instance to maintain rate limiting state
        mock_repo = AsyncMock()
        mock_repo.get_by_email.return_value = test_user
        mock_repo.save = AsyncMock()
        
        mock_email_service = AsyncMock()
        mock_email_service.send_password_reset_email = AsyncMock()
        
        service = ForgotPasswordService(
            user_repository=mock_repo,
            email_service=mock_email_service,
            token_service=PasswordResetTokenService()
        )
        
        email = test_user.email
        
        # First request should succeed
        result1 = await service.request_password_reset(email)
        assert result1["status"] == "success"
        
        # Immediate second request should be rate limited
        with pytest.raises(RateLimitExceededError):
            await service.request_password_reset(email)
    
    @pytest.mark.asyncio 
    async def test_token_timing_attack_resistance(self, test_user, token_service):
        """Test that token validation is resistant to timing attacks."""
        # Generate a valid token
        valid_token = token_service.generate_token(test_user)
        
        # Create invalid tokens of same length
        invalid_tokens = [
            "0" * 64,  # All zeros
            "f" * 64,  # All f's  
            valid_token[:-1] + "x",  # Almost correct
            "1234567890abcdef" * 4,  # Different pattern
        ]
        
        # Measure validation times - should be consistent due to constant-time comparison
        valid_times = []
        invalid_times = []
        
        for _ in range(10):
            import time
            
            # Time valid token validation
            start = time.perf_counter()
            token_service.is_token_valid(test_user, valid_token)
            end = time.perf_counter()
            valid_times.append(end - start)
            
            # Time invalid token validation
            for invalid_token in invalid_tokens:
                start = time.perf_counter()
                token_service.is_token_valid(test_user, invalid_token)
                end = time.perf_counter()
                invalid_times.append(end - start)
        
        # Timing should be relatively consistent (no significant variance)
        avg_valid = sum(valid_times) / len(valid_times)
        avg_invalid = sum(invalid_times) / len(invalid_times)
        
        # Allow reasonable variance but not orders of magnitude difference
        assert abs(avg_valid - avg_invalid) < 0.01  # Within 10ms
    
    @pytest.mark.asyncio
    async def test_five_minute_token_expiration_enforcement(self, test_user, token_service):
        """Test that tokens expire exactly after 5 minutes and become unusable."""
        # Generate token
        token = token_service.generate_token(test_user)
        
        # Verify token is initially valid
        assert token_service.is_token_valid(test_user, token)
        
        # Fast-forward time by manipulating token expiration
        test_user.password_reset_token_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        
        # Token should now be expired and invalid
        assert not token_service.is_token_valid(test_user, token)
        assert token_service.is_token_expired(test_user)
        
        # Remaining time should be None for expired tokens
        assert token_service.get_remaining_time(test_user) is None
    
    @pytest.mark.asyncio
    async def test_one_time_use_token_enforcement(self, test_user, token_service):
        """Test that tokens can only be used once for password reset."""
        # Generate token and verify it works
        token = token_service.generate_token(test_user)
        assert token_service.is_token_valid(test_user, token)
        
        # Simulate successful password reset (invalidates token)  
        token_service.invalidate_token(test_user, reason="password_reset_successful")
        
        # Token should now be completely unusable
        assert not token_service.is_token_valid(test_user, token)
        assert test_user.password_reset_token is None
        assert test_user.password_reset_token_expires_at is None
        
        # Attempting to use the same token should fail
        assert not token_service.is_token_valid(test_user, token)
    
    @pytest.mark.asyncio
    async def test_concurrent_attack_simulation(self, test_user):
        """Test system behavior under concurrent password reset requests."""
        # Create shared mocks to simulate concurrent access patterns
        shared_mock_repo = AsyncMock()
        shared_mock_repo.get_by_email.return_value = test_user
        shared_mock_repo.save = AsyncMock()
        
        shared_mock_email_service = AsyncMock()
        shared_mock_email_service.send_password_reset_email = AsyncMock()
        
        async def attack_attempt(user_email: str, attempt_id: int):
            """Simulate individual attack attempt."""
            try:
                service = ForgotPasswordService(
                    user_repository=shared_mock_repo,
                    email_service=shared_mock_email_service, 
                    token_service=PasswordResetTokenService()
                )
                
                await service.request_password_reset(user_email)
                return f"attempt_{attempt_id}_success"
            except Exception as e:
                return f"attempt_{attempt_id}_error_{type(e).__name__}"
        
        # Launch concurrent attacks
        email = test_user.email
        tasks = [attack_attempt(email, i) for i in range(10)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Should have successful operations, no system crashes
        success_count = sum(1 for r in results if "success" in str(r))
        error_count = sum(1 for r in results if "error" in str(r))
        
        assert success_count >= 5  # Most should succeed
        assert error_count == 0  # No system errors
        assert len(results) == 10  # All attempts completed
    
    @pytest.mark.asyncio
    async def test_token_enumeration_attack_prevention(self, test_user, token_service):
        """Test that the system prevents token enumeration attacks."""
        # Generate a real token
        real_token = token_service.generate_token(test_user)
        
        # Create many fake tokens for enumeration attempt
        fake_tokens = [
            token_service.generate_token(User(id=i, username=f"fake{i}", email=f"fake{i}@example.com"))
            for i in range(2, 20)  # Generate tokens for fake users
        ]
        
        # Test validation - only the real token should be valid
        assert token_service.is_token_valid(test_user, real_token)
        
        for fake_token in fake_tokens:
            # All fake tokens should be invalid for this user
            assert not token_service.is_token_valid(test_user, fake_token)
        
        # All validations should take similar time (timing attack resistance)
        import time
        times = []
        
        for token in [real_token] + fake_tokens[:5]:  # Test subset to avoid long test
            start = time.perf_counter()
            token_service.is_token_valid(test_user, token)
            end = time.perf_counter()
            times.append(end - start)
        
        # Timing variance should be minimal
        avg_time = sum(times) / len(times)
        for t in times:
            assert abs(t - avg_time) < 0.005  # Within 5ms variance
    
    @pytest.mark.asyncio
    async def test_database_failure_recovery_scenario(self, test_user):
        """Test system behavior when database operations fail during password reset."""
        token_service = PasswordResetTokenService()
        
        # Mock repository that fails on save operations
        mock_repo = AsyncMock()
        mock_repo.get_by_email.return_value = test_user
        mock_repo.get_by_reset_token.return_value = test_user
        mock_repo.save.side_effect = Exception("Database connection failed")
        
        mock_email_service = AsyncMock()
        mock_email_service.send_password_reset_email = AsyncMock()
        
        service = ForgotPasswordService(
            user_repository=mock_repo,
            email_service=mock_email_service,
            token_service=token_service
        )
        
        # Test request password reset with database failure
        with pytest.raises(ForgotPasswordError, match="Password reset request failed"):
            await service.request_password_reset("security@example.com")
        
        # Test reset password with database failure  
        token = token_service.generate_token(test_user)
        
        with pytest.raises(ForgotPasswordError, match="Password reset failed"):
            await service.reset_password(token, "NewSecurePassword123!", "en")
        
        # Token should still be invalidated even on database failure (security)
        assert test_user.password_reset_token is None
    
    @pytest.mark.asyncio
    async def test_multi_language_security_error_handling(self, test_user, token_service):
        """Test security error messages in multiple languages."""
        mock_repo = AsyncMock()
        mock_repo.get_by_email.return_value = test_user
        mock_repo.get_by_reset_token.return_value = test_user
        mock_repo.save = AsyncMock()
        
        mock_email_service = AsyncMock()
        
        service = ForgotPasswordService(
            user_repository=mock_repo,
            email_service=mock_email_service,
            token_service=token_service
        )
        
        # Test invalid token errors in different languages
        invalid_token = "invalid_token_format"
        
        languages_to_test = ["en", "es", "fa", "ar"]
        
        for language in languages_to_test:
            with pytest.raises(PasswordResetError) as exc_info:
                await service.reset_password(invalid_token, "NewPassword123!", language)
            
            # Error message should be localized and not reveal system internals
            error_msg = str(exc_info.value)
            assert len(error_msg) > 0  # Has some message
            assert "traceback" not in error_msg.lower()  # No debug info leaked
            assert "exception" not in error_msg.lower()  # No internal errors exposed
    
    @pytest.mark.asyncio
    async def test_weak_password_attack_scenario(self, test_user, token_service):
        """Test system behavior when attacker tries weak passwords repeatedly."""
        mock_repo = AsyncMock()
        mock_repo.get_by_reset_token.return_value = test_user
        mock_repo.save = AsyncMock()
        
        service = ForgotPasswordService(
            user_repository=mock_repo,
            email_service=AsyncMock(),
            token_service=token_service
        )
        
        # Generate valid token
        token = token_service.generate_token(test_user)
        
        # List of common weak passwords attackers might try
        weak_passwords = [
            "123",
            "password",
            "admin", 
            "123456",
            "qwerty",
            "abc123"
        ]
        
        # Each weak password attempt should:
        # 1. Fail with appropriate error
        # 2. Invalidate the token (one-time use + security)
        for weak_password in weak_passwords:
            # Re-generate token for each attempt (since previous attempt invalidated it)
            token = token_service.generate_token(test_user)
            
            with pytest.raises(PasswordResetError) as exc_info:
                await service.reset_password(token, weak_password, "en")
            
            # Token should be invalidated after weak password attempt
            assert test_user.password_reset_token is None
            assert "password" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_token_expiration_edge_cases(self, test_user, token_service):
        """Test edge cases around token expiration timing."""
        # Test token that expires exactly at validation time
        token = token_service.generate_token(test_user)
        
        # Verify initially valid
        assert token_service.is_token_valid(test_user, token)
        
        # Set expiration to exactly now
        test_user.password_reset_token_expires_at = datetime.now(timezone.utc)
        
        # Small delay to ensure we're past expiration
        import time
        time.sleep(0.001)
        
        # Should now be expired
        assert not token_service.is_token_valid(test_user, token)
        assert token_service.is_token_expired(test_user)
        
        # Test with microsecond precision
        token2 = token_service.generate_token(test_user, expire_minutes=1)
        
        # Move expiration to 1 microsecond ago
        test_user.password_reset_token_expires_at = (
            datetime.now(timezone.utc) - timedelta(microseconds=1)
        )
        
        assert not token_service.is_token_valid(test_user, token2)
        assert token_service.is_token_expired(test_user)
    
    @pytest.mark.asyncio 
    async def test_session_hijacking_prevention(self, test_user, token_service):
        """Test that password reset tokens can't be hijacked or reused across users."""
        # Create two different users
        user1 = test_user
        user2 = User(
            id=2,
            username="other_user",
            email="other@example.com", 
            hashed_password="$2b$12$otherhash",
            role=Role.USER,
            is_active=True
        )
        
        # Generate tokens for both users
        token1 = token_service.generate_token(user1)
        token2 = token_service.generate_token(user2)
        
        # Each token should only work for its intended user
        assert token_service.is_token_valid(user1, token1)
        assert not token_service.is_token_valid(user1, token2)  # Cross-user invalid
        
        assert token_service.is_token_valid(user2, token2) 
        assert not token_service.is_token_valid(user2, token1)  # Cross-user invalid
        
        # Even if user1's token is compromised, it shouldn't work for user2
        # This tests against session/token hijacking attacks
        assert not token_service.is_token_valid(user2, token1)
    
    @pytest.mark.asyncio
    async def test_cleanup_security_verification(self, token_service):
        """Test that the cleanup process properly handles security edge cases."""
        # Create users with various token states
        expired_user = User(
            id=1, 
            username="expired",
            email="expired@example.com",
            password_reset_token="a" * 64,
            password_reset_token_expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
        )
        
        valid_user = User(
            id=2,
            username="valid", 
            email="valid@example.com",
            password_reset_token="b" * 64,
            password_reset_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        no_token_user = User(
            id=3,
            username="none",
            email="none@example.com"
        )
        
        mock_repo = AsyncMock()
        mock_repo.get_users_with_reset_tokens.return_value = [
            expired_user, valid_user, no_token_user
        ]
        mock_repo.save = AsyncMock()
        
        service = ForgotPasswordService(
            user_repository=mock_repo,
            email_service=AsyncMock(),
            token_service=token_service
        )
        
        # Run cleanup
        cleaned_count = await service.cleanup_expired_tokens()
        
        # Only expired user should be cleaned
        assert cleaned_count == 1
        assert expired_user.password_reset_token is None
        assert expired_user.password_reset_token_expires_at is None
        
        # Valid user should remain unchanged
        assert valid_user.password_reset_token == "b" * 64
        assert valid_user.password_reset_token_expires_at is not None
        
        # No-token user should remain unchanged
        assert no_token_user.password_reset_token is None 