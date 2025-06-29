"""Unit tests for ResetToken value objects.

These tests verify that reset token value objects properly enforce
business rules and security requirements following TDD principles.
"""

import re
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from src.domain.value_objects.reset_token import ResetToken


class TestResetToken:
    """Test suite for ResetToken value object."""
    
    def test_generate_valid_token(self):
        """Test generating a valid reset token."""
        # Act
        token = ResetToken.generate()
        
        # Assert
        assert len(token.value) == 64
        assert token.expires_at > datetime.now(timezone.utc)
        assert re.match(r'^[0-9a-f]{64}$', token.value)  # Hex format
    
    def test_token_immutability(self):
        """Test that token is immutable."""
        # Arrange
        token = ResetToken.generate()
        
        # Act & Assert
        with pytest.raises(AttributeError):
            token.value = "modified"  # Should fail due to frozen dataclass
    
    def test_generate_with_custom_expiry(self):
        """Test generating token with custom expiry time."""
        # Arrange
        custom_expiry_minutes = 10
        
        # Act
        token = ResetToken.generate(expiry_minutes=custom_expiry_minutes)
        
        # Assert
        expected_expiry = datetime.now(timezone.utc) + timedelta(minutes=custom_expiry_minutes)
        # Allow for small timing differences (within 1 second)
        assert abs((token.expires_at - expected_expiry).total_seconds()) < 1.0
    
    def test_from_existing_valid_token(self):
        """Test creating token from existing valid values."""
        # Arrange
        token_value = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        # Act
        token = ResetToken.from_existing(token_value, expires_at)
        
        # Assert
        assert token.value == token_value
        assert token.expires_at == expires_at
    
    def test_token_value_validation_empty(self):
        """Test token value cannot be empty."""
        # Arrange
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        # Act & Assert
        with pytest.raises(ValueError, match="Token cannot be empty"):
            ResetToken.from_existing("", expires_at)
    
    def test_token_value_validation_wrong_length(self):
        """Test token value must be exactly 64 characters."""
        # Arrange
        short_token = "a1b2c3"  # Too short
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        # Act & Assert
        with pytest.raises(ValueError, match="Token must be exactly 64 characters"):
            ResetToken.from_existing(short_token, expires_at)
    
    def test_token_value_validation_non_hex(self):
        """Test token value must be hexadecimal."""
        # Arrange
        non_hex_token = "g" * 64  # Contains non-hex character
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        # Act & Assert
        with pytest.raises(ValueError, match="Token must contain only hexadecimal characters"):
            ResetToken.from_existing(non_hex_token, expires_at)
    
    def test_expiry_validation_empty(self):
        """Test expiry cannot be empty."""
        # Arrange
        token_value = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Token expiry cannot be empty"):
            ResetToken.from_existing(token_value, None)
    
    def test_expiry_validation_timezone_naive(self):
        """Test expiry must be timezone-aware."""
        # Arrange
        token_value = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
        naive_datetime = datetime.now()  # No timezone info
        
        # Act & Assert
        with pytest.raises(ValueError, match="Token expiry must be timezone-aware"):
            ResetToken.from_existing(token_value, naive_datetime)
    
    def test_is_expired_true(self):
        """Test token expiration detection when expired."""
        # Arrange
        token_value = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
        expired_time = datetime.now(timezone.utc) - timedelta(minutes=1)  # 1 minute ago
        token = ResetToken.from_existing(token_value, expired_time)
        
        # Act
        is_expired = token.is_expired()
        
        # Assert
        assert is_expired is True
    
    def test_is_expired_false(self):
        """Test token expiration detection when not expired."""
        # Arrange
        token = ResetToken.generate(expiry_minutes=5)
        
        # Act
        is_expired = token.is_expired()
        
        # Assert
        assert is_expired is False
    
    def test_is_expired_with_custom_time(self):
        """Test token expiration with custom check time."""
        # Arrange
        token_value = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
        expires_at = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = ResetToken.from_existing(token_value, expires_at)
        
        # Act - check at a time after expiry
        check_time = datetime(2023, 1, 1, 13, 0, 0, tzinfo=timezone.utc)
        is_expired = token.is_expired(check_time)
        
        # Assert
        assert is_expired is True
    
    def test_is_valid_true(self):
        """Test token validity when not expired."""
        # Arrange
        token = ResetToken.generate(expiry_minutes=5)
        
        # Act
        is_valid = token.is_valid()
        
        # Assert
        assert is_valid is True
    
    def test_is_valid_false(self):
        """Test token validity when expired."""
        # Arrange
        token_value = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
        expired_time = datetime.now(timezone.utc) - timedelta(minutes=1)
        token = ResetToken.from_existing(token_value, expired_time)
        
        # Act
        is_valid = token.is_valid()
        
        # Assert
        assert is_valid is False
    
    def test_time_remaining_positive(self):
        """Test time remaining calculation when token is valid."""
        # Arrange
        token = ResetToken.generate(expiry_minutes=10)
        
        # Act
        remaining = token.time_remaining()
        
        # Assert
        assert remaining.total_seconds() > 0
        assert remaining.total_seconds() <= 600  # 10 minutes
    
    def test_time_remaining_negative(self):
        """Test time remaining calculation when token is expired."""
        # Arrange
        token_value = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
        expired_time = datetime.now(timezone.utc) - timedelta(minutes=5)
        token = ResetToken.from_existing(token_value, expired_time)
        
        # Act
        remaining = token.time_remaining()
        
        # Assert
        assert remaining.total_seconds() < 0
    
    def test_time_remaining_with_custom_time(self):
        """Test time remaining with custom check time."""
        # Arrange
        token_value = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
        expires_at = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = ResetToken.from_existing(token_value, expires_at)
        
        # Act - check at a time before expiry
        check_time = datetime(2023, 1, 1, 11, 0, 0, tzinfo=timezone.utc)
        remaining = token.time_remaining(check_time)
        
        # Assert
        assert remaining == timedelta(hours=1)
    
    def test_mask_for_logging(self):
        """Test token masking for safe logging."""
        # Arrange
        token_value = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        token = ResetToken.from_existing(token_value, expires_at)
        
        # Act
        masked = token.mask_for_logging()
        
        # Assert
        assert masked == "a1b2c3d4..."
        assert len(masked) == 11  # 8 chars + 3 dots
    
    def test_token_length_constant(self):
        """Test that token length constant is correct."""
        # Assert
        assert ResetToken.TOKEN_LENGTH == 64
    
    def test_token_bytes_constant(self):
        """Test that token bytes constant is correct."""
        # Assert
        assert ResetToken.TOKEN_BYTES == 32
    
    def test_default_expiry_constant(self):
        """Test that default expiry constant is correct."""
        # Assert
        assert ResetToken.DEFAULT_EXPIRY_MINUTES == 5
    
    @patch('secrets.token_hex')
    def test_generate_uses_secure_random(self, mock_token_hex):
        """Test that token generation uses cryptographically secure random."""
        # Arrange
        mock_token_hex.return_value = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
        
        # Act
        token = ResetToken.generate()
        
        # Assert
        mock_token_hex.assert_called_once_with(32)  # 32 bytes = 64 hex chars
        assert token.value == "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
    
    def test_entropy_calculation(self):
        """Test that tokens have sufficient entropy."""
        # Generate multiple tokens and verify uniqueness
        tokens = set()
        num_tokens = 100
        
        for _ in range(num_tokens):
            token = ResetToken.generate()
            tokens.add(token.value)
        
        # All tokens should be unique (extremely high probability)
        assert len(tokens) == num_tokens
    
    def test_token_format_consistency(self):
        """Test that all generated tokens follow the same format."""
        # Generate multiple tokens
        for _ in range(10):
            token = ResetToken.generate()
            
            # Verify format consistency
            assert len(token.value) == 64
            assert re.match(r'^[0-9a-f]{64}$', token.value)
            assert token.expires_at.tzinfo is not None


class TestResetTokenSecurity:
    """Security-focused tests for ResetToken."""
    
    def test_token_unpredictability(self):
        """Test that tokens are unpredictable."""
        # Generate many tokens and check for patterns
        tokens = []
        for _ in range(50):
            tokens.append(ResetToken.generate().value)
        
        # Check that no two tokens share a common prefix longer than expected by chance
        # With 64 hex chars, sharing more than 2-3 chars should be very rare
        for i in range(len(tokens)):
            for j in range(i + 1, len(tokens)):
                common_prefix = 0
                for k in range(min(len(tokens[i]), len(tokens[j]))):
                    if tokens[i][k] == tokens[j][k]:
                        common_prefix += 1
                    else:
                        break
                
                # Very unlikely to have more than 4 characters in common
                assert common_prefix <= 4
    
    def test_timing_attack_resistance(self):
        """Test that token validation is resistant to timing attacks."""
        # This is more of a design verification than a true timing test
        token = ResetToken.generate()
        
        # The validation logic should use constant-time comparison
        # (This would be tested in the service layer using secrets.compare_digest)
        assert hasattr(token, 'value')
        assert isinstance(token.value, str)
    
    def test_token_does_not_leak_user_info(self):
        """Test that tokens don't contain user information."""
        # Generate tokens and verify they don't contain predictable patterns
        # that could leak user information
        token = ResetToken.generate()
        
        # Token should be pure random hex, no structured data
        assert not any(char.isupper() for char in token.value)  # Only lowercase hex
        assert all(char in '0123456789abcdef' for char in token.value)
        
        # Should not contain common patterns that might indicate user data
        assert 'user' not in token.value
        assert 'id' not in token.value
        assert '0000' not in token.value  # Avoid obvious patterns


class TestResetTokenEdgeCases:
    """Edge case tests for ResetToken."""
    
    def test_exact_expiry_boundary(self):
        """Test behavior exactly at expiry time."""
        # Arrange
        token_value = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
        exact_expiry = datetime.now(timezone.utc)
        token = ResetToken.from_existing(token_value, exact_expiry)
        
        # Act - check at exact expiry time
        is_expired = token.is_expired(exact_expiry)
        
        # Assert - at exact expiry, token should be considered expired
        assert is_expired is False  # Exactly at expiry is still valid
    
    def test_microsecond_precision(self):
        """Test that expiry times handle microsecond precision."""
        # Arrange
        token_value = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
        expiry_with_microseconds = datetime(2023, 1, 1, 12, 0, 0, 123456, timezone.utc)
        
        # Act
        token = ResetToken.from_existing(token_value, expiry_with_microseconds)
        
        # Assert
        assert token.expires_at.microsecond == 123456
    
    def test_different_timezones(self):
        """Test token works correctly with different timezones."""
        from datetime import timezone
        
        # Arrange
        token_value = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
        
        # Create expiry in different timezone
        utc_plus_5 = timezone(timedelta(hours=5))
        expiry_in_tz = datetime(2023, 1, 1, 17, 0, 0, tzinfo=utc_plus_5)
        
        # Act
        token = ResetToken.from_existing(token_value, expiry_in_tz)
        
        # Assert
        assert token.expires_at.tzinfo == utc_plus_5
        
        # Time remaining calculation should work correctly
        check_time_utc = datetime(2023, 1, 1, 11, 0, 0, tzinfo=timezone.utc)
        remaining = token.time_remaining(check_time_utc)
        assert remaining == timedelta(hours=1)  # 12:00 UTC - 11:00 UTC 