"""Enhanced Password Reset Token Service Tests.

This module tests the enhanced PasswordResetTokenService with rate limiting
and improved security features following DDD and TDD principles.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, Mock, patch

from src.core.exceptions import RateLimitExceededError
from src.domain.entities.user import User
from src.domain.interfaces.services import IRateLimitingService
from src.domain.value_objects.reset_token import ResetToken
from src.infrastructure.services.password_reset_token_service import PasswordResetTokenService

@pytest.fixture
def mock_rate_limiting_service():
    service = Mock(spec=IRateLimitingService)
    service.is_user_rate_limited = AsyncMock(return_value=False)
    service.record_attempt = AsyncMock()
    service.get_time_until_reset = AsyncMock(return_value=None)
    return service

@pytest.fixture
def token_service_with_rate_limiting(mock_rate_limiting_service):
    return PasswordResetTokenService(
        token_expiry_minutes=5,
        rate_limiting_service=mock_rate_limiting_service
    )

class TestEnhancedPasswordResetTokenService:
    """Test enhanced password reset token service with rate limiting."""
    
    @pytest.fixture
    def token_service_without_rate_limiting(self):
        """Create token service without rate limiting."""
        return PasswordResetTokenService(token_expiry_minutes=5)
    
    @pytest.fixture
    def test_user(self):
        """Create a test user."""
        user = User(
            id=1,
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            is_active=True
        )
        return user
    
    @pytest.mark.asyncio
    async def test_generate_token_with_rate_limiting_success(self, token_service_with_rate_limiting, test_user):
        """Test successful token generation with rate limiting enabled."""
        # Act
        token = await token_service_with_rate_limiting.generate_token(test_user)
        
        # Assert
        assert isinstance(token, ResetToken)
        assert token.value is not None
        assert len(token.value) >= ResetToken.MIN_TOKEN_LENGTH
        assert len(token.value) <= ResetToken.MAX_TOKEN_LENGTH
        assert test_user.password_reset_token == token.value
        assert test_user.password_reset_token_expires_at == token.expires_at
        
        # Verify rate limiting was checked and recorded
        token_service_with_rate_limiting._rate_limiting_service.is_user_rate_limited.assert_called_once_with(test_user.id)
        token_service_with_rate_limiting._rate_limiting_service.record_attempt.assert_called_once_with(test_user.id)
    
    @pytest.mark.asyncio
    async def test_generate_token_without_rate_limiting_success(self, token_service_without_rate_limiting, test_user):
        """Test successful token generation without rate limiting."""
        # Act
        token = await token_service_without_rate_limiting.generate_token(test_user)
        
        # Assert
        assert isinstance(token, ResetToken)
        assert token.value is not None
        assert len(token.value) >= ResetToken.MIN_TOKEN_LENGTH
        assert len(token.value) <= ResetToken.MAX_TOKEN_LENGTH
        assert test_user.password_reset_token == token.value
        assert test_user.password_reset_token_expires_at == token.expires_at
    
    @pytest.mark.asyncio
    async def test_generate_token_rate_limit_exceeded(self, mock_rate_limiting_service, test_user):
        """Test token generation when rate limit is exceeded."""
        # Arrange
        mock_rate_limiting_service.is_user_rate_limited.return_value = True
        mock_rate_limiting_service.get_time_until_reset.return_value = datetime.now(timezone.utc)
        
        token_service = PasswordResetTokenService(
            token_expiry_minutes=5,
            rate_limiting_service=mock_rate_limiting_service
        )
        
        # Act & Assert
        with pytest.raises(RateLimitExceededError, match="Too many password reset attempts"):
            await token_service.generate_token(test_user)
        
        # Verify rate limiting was checked but not recorded
        mock_rate_limiting_service.is_user_rate_limited.assert_called_once_with(test_user.id)
        mock_rate_limiting_service.record_attempt.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_generate_token_rate_limit_service_error_fail_open(self, mock_rate_limiting_service, test_user):
        """Test that rate limiting errors don't block token generation (fail open)."""
        # Arrange
        mock_rate_limiting_service.is_user_rate_limited.side_effect = Exception("Rate limit service error")
        
        token_service = PasswordResetTokenService(
            token_expiry_minutes=5,
            rate_limiting_service=mock_rate_limiting_service
        )
        
        # Act
        token = await token_service.generate_token(test_user)
        
        # Assert - should still generate token despite rate limit error
        assert isinstance(token, ResetToken)
        assert token.value is not None
        assert test_user.password_reset_token == token.value
    
    @pytest.mark.asyncio
    async def test_generate_token_replaces_existing_token(self, token_service_with_rate_limiting, test_user):
        """Test that generating a new token replaces existing token."""
        # Arrange - set existing token
        test_user.password_reset_token = "old_token"
        test_user.password_reset_token_expires_at = datetime.now(timezone.utc)
        
        # Act
        new_token = await token_service_with_rate_limiting.generate_token(test_user)
        
        # Assert
        assert new_token.value != "old_token"
        assert test_user.password_reset_token == new_token.value
        assert test_user.password_reset_token_expires_at == new_token.expires_at
    
    def test_validate_token_success(self, token_service_with_rate_limiting, test_user):
        """Test successful token validation."""
        # Arrange
        token = ResetToken.generate()
        test_user.password_reset_token = token.value
        test_user.password_reset_token_expires_at = token.expires_at
        
        # Act
        is_valid = token_service_with_rate_limiting.validate_token(test_user, token.value)
        
        # Assert
        assert is_valid is True
    
    def test_validate_token_invalid_token(self, token_service_with_rate_limiting, test_user):
        """Test token validation with invalid token."""
        # Arrange
        token = ResetToken.generate()
        test_user.password_reset_token = token.value
        test_user.password_reset_token_expires_at = token.expires_at
        
        # Act
        is_valid = token_service_with_rate_limiting.validate_token(test_user, "invalid_token")
        
        # Assert
        assert is_valid is False
    
    def test_validate_token_no_active_token(self, token_service_with_rate_limiting, test_user):
        """Test token validation when user has no active token."""
        # Arrange
        test_user.password_reset_token = None
        test_user.password_reset_token_expires_at = None
        
        # Act
        is_valid = token_service_with_rate_limiting.validate_token(test_user, "any_token")
        
        # Assert
        assert is_valid is False
    
    def test_validate_token_expired_token(self, token_service_with_rate_limiting, test_user):
        """Test token validation with expired token."""
        # Arrange
        expired_token = ResetToken.generate()
        # Manually set expired time
        expired_token = ResetToken(
            value=expired_token.value,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        test_user.password_reset_token = expired_token.value
        test_user.password_reset_token_expires_at = expired_token.expires_at
        
        # Act
        is_valid = token_service_with_rate_limiting.validate_token(test_user, expired_token.value)
        
        # Assert
        assert is_valid is False
    
    def test_invalidate_token_success(self, token_service_with_rate_limiting, test_user):
        """Test successful token invalidation."""
        # Arrange
        token = ResetToken.generate()
        test_user.password_reset_token = token.value
        test_user.password_reset_token_expires_at = token.expires_at
        
        # Act
        token_service_with_rate_limiting.invalidate_token(test_user, "test_reason")
        
        # Assert
        assert test_user.password_reset_token is None
        assert test_user.password_reset_token_expires_at is None
    
    def test_invalidate_token_no_active_token(self, token_service_with_rate_limiting, test_user):
        """Test token invalidation when no active token exists."""
        # Arrange
        test_user.password_reset_token = None
        test_user.password_reset_token_expires_at = None
        
        # Act - should not raise error
        token_service_with_rate_limiting.invalidate_token(test_user, "test_reason")
        
        # Assert - should remain None
        assert test_user.password_reset_token is None
        assert test_user.password_reset_token_expires_at is None
    
    def test_is_token_expired_with_active_token(self, token_service_with_rate_limiting, test_user):
        """Test token expiration check with active token."""
        # Arrange
        token = ResetToken.generate()
        test_user.password_reset_token = token.value
        test_user.password_reset_token_expires_at = token.expires_at
        
        # Act
        is_expired = token_service_with_rate_limiting.is_token_expired(test_user)
        
        # Assert
        assert is_expired is False
    
    def test_is_token_expired_with_expired_token(self, token_service_with_rate_limiting, test_user):
        """Test token expiration check with expired token."""
        # Arrange
        expired_token = ResetToken.generate()
        expired_token = ResetToken(
            value=expired_token.value,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        test_user.password_reset_token = expired_token.value
        test_user.password_reset_token_expires_at = expired_token.expires_at
        
        # Act
        is_expired = token_service_with_rate_limiting.is_token_expired(test_user)
        
        # Assert
        assert is_expired is True
    
    def test_is_token_expired_no_token(self, token_service_with_rate_limiting, test_user):
        """Test token expiration check with no token."""
        # Arrange
        test_user.password_reset_token = None
        test_user.password_reset_token_expires_at = None
        
        # Act
        is_expired = token_service_with_rate_limiting.is_token_expired(test_user)
        
        # Assert
        assert is_expired is True
    
    def test_get_token_expiry_with_token(self, token_service_with_rate_limiting, test_user):
        """Test getting token expiry with active token."""
        # Arrange
        token = ResetToken.generate()
        test_user.password_reset_token = token.value
        test_user.password_reset_token_expires_at = token.expires_at
        
        # Act
        expiry = token_service_with_rate_limiting.get_token_expiry(test_user)
        
        # Assert
        assert expiry == token.expires_at
    
    def test_get_token_expiry_no_token(self, token_service_with_rate_limiting, test_user):
        """Test getting token expiry with no token."""
        # Arrange
        test_user.password_reset_token = None
        test_user.password_reset_token_expires_at = None
        
        # Act
        expiry = token_service_with_rate_limiting.get_token_expiry(test_user)
        
        # Assert
        assert expiry is None
    
    def test_get_time_remaining_with_valid_token(self, token_service_with_rate_limiting, test_user):
        """Test getting time remaining with valid token."""
        # Arrange
        token = ResetToken.generate(expiry_minutes=10)
        test_user.password_reset_token = token.value
        test_user.password_reset_token_expires_at = token.expires_at
        
        # Act
        remaining = token_service_with_rate_limiting.get_time_remaining(test_user)
        
        # Assert
        assert remaining is not None
        assert remaining > 0
        assert remaining <= 600  # 10 minutes in seconds
    
    def test_get_time_remaining_no_token(self, token_service_with_rate_limiting, test_user):
        """Test getting time remaining with no token."""
        # Arrange
        test_user.password_reset_token = None
        test_user.password_reset_token_expires_at = None
        
        # Act
        remaining = token_service_with_rate_limiting.get_time_remaining(test_user)
        
        # Assert
        assert remaining is None
    
    def test_get_token_security_metrics_with_token(self, token_service_with_rate_limiting, test_user):
        """Test getting security metrics with active token."""
        # Arrange
        token = ResetToken.generate()
        test_user.password_reset_token = token.value
        test_user.password_reset_token_expires_at = token.expires_at
        
        # Act
        metrics = token_service_with_rate_limiting.get_token_security_metrics(test_user)
        
        # Assert
        assert metrics is not None
        assert 'length' in metrics
        assert 'character_diversity' in metrics
        assert 'unique_characters' in metrics
        assert 'entropy_bits' in metrics
        assert 'format_unpredictable' in metrics
    
    def test_get_token_security_metrics_no_token(self, token_service_with_rate_limiting, test_user):
        """Test getting security metrics with no token."""
        # Arrange
        test_user.password_reset_token = None
        test_user.password_reset_token_expires_at = None
        
        # Act
        metrics = token_service_with_rate_limiting.get_token_security_metrics(test_user)
        
        # Assert
        assert metrics is None
    
    def test_has_active_token_with_token(self, token_service_with_rate_limiting, test_user):
        """Test checking for active token when token exists."""
        # Arrange
        token = ResetToken.generate()
        test_user.password_reset_token = token.value
        test_user.password_reset_token_expires_at = token.expires_at
        
        # Act
        has_token = token_service_with_rate_limiting._has_active_token(test_user)
        
        # Assert
        assert has_token is True
    
    def test_has_active_token_no_token(self, token_service_with_rate_limiting, test_user):
        """Test checking for active token when no token exists."""
        # Arrange
        test_user.password_reset_token = None
        test_user.password_reset_token_expires_at = None
        
        # Act
        has_token = token_service_with_rate_limiting._has_active_token(test_user)
        
        # Assert
        assert has_token is False
    
    def test_has_active_token_partial_token(self, token_service_with_rate_limiting, test_user):
        """Test checking for active token with partial token data."""
        # Arrange - only token value, no expiry
        test_user.password_reset_token = "some_token"
        test_user.password_reset_token_expires_at = None
        
        # Act
        has_token = token_service_with_rate_limiting._has_active_token(test_user)
        
        # Assert
        assert has_token is False
    
    @pytest.mark.asyncio
    async def test_generate_token_creates_unpredictable_tokens(self, token_service_with_rate_limiting, test_user):
        """Test that generated tokens are unpredictable."""
        # Act
        tokens = []
        for _ in range(10):
            token = await token_service_with_rate_limiting.generate_token(test_user)
            tokens.append(token.value)
        
        # Assert
        # All tokens should be unique
        assert len(set(tokens)) == len(tokens)
        
        # Tokens should have different lengths (unpredictable)
        lengths = [len(token) for token in tokens]
        assert len(set(lengths)) > 1
        
        # Tokens should have different character distributions
        char_distributions = []
        for token_value in tokens:
            distribution = {
                'uppercase': sum(1 for c in token_value if c.isupper()),
                'lowercase': sum(1 for c in token_value if c.islower()),
                'digits': sum(1 for c in token_value if c.isdigit()),
                'special': sum(1 for c in token_value if not c.isalnum())
            }
            char_distributions.append(distribution)
        
        # Should have different distributions
        assert len(set(str(d) for d in char_distributions)) > 1
    
    @pytest.mark.asyncio
    async def test_generate_token_with_custom_expiry(self, mock_rate_limiting_service, test_user):
        """Test token generation with custom expiry time."""
        # Arrange
        custom_expiry = 15
        token_service = PasswordResetTokenService(
            token_expiry_minutes=custom_expiry,
            rate_limiting_service=mock_rate_limiting_service
        )
        
        # Act
        token = await token_service.generate_token(test_user)
        
        # Assert
        expected_expiry = datetime.now(timezone.utc) + timedelta(minutes=custom_expiry)
        assert abs((token.expires_at - expected_expiry).total_seconds()) < 1


class TestEnhancedPasswordResetTokenServiceErrorHandling:
    """Test error handling in enhanced password reset token service."""
    
    @pytest.fixture
    def test_user(self):
        """Create a test user."""
        user = User(
            id=1,
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            is_active=True
        )
        return user
    
    @pytest.mark.asyncio
    async def test_generate_token_handles_token_generation_error(self, test_user):
        """Test handling of token generation errors."""
        # Arrange
        token_service = PasswordResetTokenService()
        
        # Mock ResetToken.generate to raise an error
        with patch('src.domain.value_objects.reset_token.ResetToken.generate') as mock_generate:
            mock_generate.side_effect = Exception("Token generation failed")
            
            # Act & Assert
            with pytest.raises(Exception, match="Token generation failed"):
                await token_service.generate_token(test_user)
    
    def test_validate_token_handles_validation_error(self, test_user):
        """Test handling of token validation errors."""
        # Arrange
        token_service = PasswordResetTokenService()
        test_user.password_reset_token = "invalid_token_format"
        test_user.password_reset_token_expires_at = datetime.now(timezone.utc)
        
        # Act
        is_valid = token_service.validate_token(test_user, "any_token")
        
        # Assert - should return False on validation error
        assert is_valid is False
    
    def test_invalidate_token_handles_error(self, test_user):
        """Test handling of token invalidation errors."""
        # Arrange
        token_service = PasswordResetTokenService()
        test_user.password_reset_token = "some_token"
        test_user.password_reset_token_expires_at = datetime.now(timezone.utc)

        # Mock user attribute to raise error when accessed for logging
        # The service accesses user.password_reset_token[:8] for logging
        mock_token = Mock()
        mock_token.__getitem__ = Mock(side_effect=Exception("Database error"))
        test_user.password_reset_token = mock_token

        # Act & Assert
        with pytest.raises(Exception, match="Database error"):
            token_service.invalidate_token(test_user, "test_reason")
    
    def test_get_time_remaining_handles_error(self, test_user):
        """Test handling of time remaining calculation errors."""
        # Arrange
        token_service = PasswordResetTokenService()
        test_user.password_reset_token = "invalid_token"
        test_user.password_reset_token_expires_at = datetime.now(timezone.utc)
        
        # Act
        remaining = token_service.get_time_remaining(test_user)
        
        # Assert - should return None on error
        assert remaining is None


class TestEnhancedPasswordResetTokenServiceSecurity:
    """Test security aspects of enhanced password reset token service."""
    
    @pytest.fixture
    def test_user(self):
        """Create a test user."""
        user = User(
            id=1,
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            is_active=True
        )
        return user
    
    @pytest.mark.asyncio
    async def test_generate_token_uses_constant_time_comparison(self, token_service_with_rate_limiting, test_user):
        """Test that token validation uses constant-time comparison."""
        # Arrange
        token = await token_service_with_rate_limiting.generate_token(test_user)
        
        # Act - validate with correct token
        start_time = datetime.now()
        is_valid_correct = token_service_with_rate_limiting.validate_token(test_user, token.value)
        correct_time = (datetime.now() - start_time).total_seconds()
        
        # Act - validate with incorrect token
        start_time = datetime.now()
        is_valid_incorrect = token_service_with_rate_limiting.validate_token(test_user, "wrong_token")
        incorrect_time = (datetime.now() - start_time).total_seconds()
        
        # Assert
        assert is_valid_correct is True
        assert is_valid_incorrect is False
        
        # Times should be similar (constant-time comparison)
        # Allow some tolerance for system variations
        time_diff = abs(correct_time - incorrect_time)
        assert time_diff < 0.1  # 100ms tolerance
    
    @pytest.mark.asyncio
    async def test_generate_token_prevents_timing_attacks(self, token_service_with_rate_limiting, test_user):
        """Test that token generation prevents timing attacks."""
        # Arrange
        token = await token_service_with_rate_limiting.generate_token(test_user)
        
        # Test with tokens of different lengths
        short_token = "short"
        long_token = "very_long_token_for_timing_test"
        
        # Act
        start_time = datetime.now()
        token_service_with_rate_limiting.validate_token(test_user, short_token)
        short_time = (datetime.now() - start_time).total_seconds()
        
        start_time = datetime.now()
        token_service_with_rate_limiting.validate_token(test_user, long_token)
        long_time = (datetime.now() - start_time).total_seconds()
        
        # Assert - times should be similar regardless of input length
        time_diff = abs(short_time - long_time)
        assert time_diff < 0.1  # 100ms tolerance
    
    @pytest.mark.asyncio
    async def test_generate_token_creates_high_entropy_tokens(self, token_service_with_rate_limiting, test_user):
        """Test that generated tokens have high entropy."""
        # Act
        token = await token_service_with_rate_limiting.generate_token(test_user)
        metrics = token.get_security_metrics()
        
        # Assert
        assert metrics['entropy_bits'] > 100  # Should have substantial entropy
        assert metrics['unique_characters'] >= 10  # Should have good character diversity
        assert metrics['format_unpredictable'] is True 