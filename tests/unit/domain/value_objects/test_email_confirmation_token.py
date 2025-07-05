"""Unit tests for EmailConfirmationToken value object.

This module tests the EmailConfirmationToken value object following
TDD principles and comprehensive test coverage.
"""

import pytest
from datetime import datetime, timezone

from src.domain.value_objects.email_confirmation_token import EmailConfirmationToken


class TestEmailConfirmationToken:
    """Test cases for EmailConfirmationToken value object."""
    
    def test_generate_token_creates_valid_token(self):
        """Test that generate() creates a valid token."""
        # Act
        token = EmailConfirmationToken.generate()
        
        # Assert
        assert isinstance(token, EmailConfirmationToken)
        assert len(token.value) == 64
        assert all(c in '0123456789abcdef' for c in token.value.lower())
        assert isinstance(token.created_at, datetime)
        assert token.created_at.tzinfo is not None
    
    def test_from_existing_with_valid_token(self):
        """Test creating token from existing valid value."""
        # Arrange
        valid_token = "a" * 64  # 64 hex characters
        
        # Act
        token = EmailConfirmationToken.from_existing(valid_token)
        
        # Assert
        assert token.value == valid_token
        assert isinstance(token.created_at, datetime)
    
    def test_from_existing_with_custom_created_at(self):
        """Test creating token with custom creation timestamp."""
        # Arrange
        valid_token = "b" * 64
        custom_time = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        
        # Act
        token = EmailConfirmationToken.from_existing(valid_token, custom_time)
        
        # Assert
        assert token.value == valid_token
        assert token.created_at == custom_time
    
    def test_validate_token_format_empty_string(self):
        """Test validation fails with empty string."""
        # Act & Assert
        with pytest.raises(ValueError, match="cannot be empty"):
            EmailConfirmationToken("")
    
    def test_validate_token_format_none_value(self):
        """Test validation fails with None value."""
        # Act & Assert
        with pytest.raises(ValueError, match="cannot be empty"):
            EmailConfirmationToken(None)
    
    def test_validate_token_format_wrong_type(self):
        """Test validation fails with non-string type."""
        # Act & Assert
        with pytest.raises(ValueError, match="must be a string"):
            EmailConfirmationToken(123)
    
    def test_validate_token_format_wrong_length(self):
        """Test validation fails with wrong length."""
        # Act & Assert
        with pytest.raises(ValueError, match="length is invalid"):
            EmailConfirmationToken("a" * 32)  # Too short
        with pytest.raises(ValueError, match="length is invalid"):
            EmailConfirmationToken("a" * 128)  # Too long
    
    def test_validate_token_format_invalid_hex(self):
        """Test validation fails with invalid hex characters."""
        # Act & Assert
        with pytest.raises(ValueError, match="format is invalid"):
            EmailConfirmationToken("g" * 64)  # 'g' is not valid hex
    
    def test_validate_token_format_valid_hex(self):
        """Test validation passes with valid hex string."""
        # Arrange
        valid_token = "0123456789abcdef" * 4  # 64 valid hex characters
        
        # Act
        token = EmailConfirmationToken(valid_token)
        
        # Assert
        assert token.value == valid_token
    
    def test_equality_same_token(self):
        """Test equality comparison with same token."""
        # Arrange
        token1 = EmailConfirmationToken("a" * 64)
        token2 = EmailConfirmationToken("a" * 64)
        
        # Act & Assert
        assert token1 == token2
        assert hash(token1) == hash(token2)
    
    def test_equality_different_tokens(self):
        """Test equality comparison with different tokens."""
        # Arrange
        token1 = EmailConfirmationToken("a" * 64)
        token2 = EmailConfirmationToken("b" * 64)
        
        # Act & Assert
        assert token1 != token2
        assert hash(token1) != hash(token2)
    
    def test_equality_different_type(self):
        """Test equality comparison with different type."""
        # Arrange
        token = EmailConfirmationToken("a" * 64)
        
        # Act & Assert
        assert token != "not a token"
        assert token != 123
    
    def test_string_representation(self):
        """Test string representation masks token for security."""
        # Arrange
        token = EmailConfirmationToken("a" * 64)
        
        # Act
        str_repr = str(token)
        
        # Assert
        assert str_repr.startswith("aaaaaaaa...")
        assert str_repr.endswith("...aaaaaaaa")
        assert len(str_repr) < 64  # Should be masked
    
    def test_repr_representation(self):
        """Test repr representation for debugging."""
        # Arrange
        token = EmailConfirmationToken("a" * 64)
        
        # Act
        repr_str = repr(token)
        
        # Assert
        assert "EmailConfirmationToken" in repr_str
        assert "aaaaaaaa..." in repr_str
        assert "created_at=" in repr_str
        assert len(repr_str) < 200  # Should be reasonable length
    
    def test_get_security_metrics(self):
        """Test security metrics generation."""
        # Arrange
        token = EmailConfirmationToken("a" * 64)
        
        # Act
        metrics = token.get_security_metrics()
        
        # Assert
        assert isinstance(metrics, dict)
        assert metrics["token_length"] == 64
        assert metrics["token_format"] == "hex"
        assert metrics["security_bits"] == 256
        assert metrics["age_seconds"] >= 0
        assert "created_at" in metrics
        assert metrics["is_secure"] is True
    
    def test_get_security_metrics_invalid_token(self):
        """Test security metrics with invalid token format."""
        # Arrange
        token = EmailConfirmationToken("a" * 64)
        # Manually modify the value to simulate invalid format
        token._value = "invalid_token"
        
        # Act
        metrics = token.get_security_metrics()
        
        # Assert
        assert metrics["is_secure"] is False
    
    def test_token_immutability(self):
        """Test that token value is immutable."""
        # Arrange
        token = EmailConfirmationToken("a" * 64)
        original_value = token.value
        
        # Act & Assert
        # Should not be able to modify the value
        with pytest.raises(AttributeError):
            token.value = "new_value"
        
        # Value should remain unchanged
        assert token.value == original_value
    
    def test_created_at_immutability(self):
        """Test that created_at timestamp is immutable."""
        # Arrange
        token = EmailConfirmationToken("a" * 64)
        original_time = token.created_at
        
        # Act & Assert
        # Should not be able to modify the timestamp
        with pytest.raises(AttributeError):
            token.created_at = datetime.now(timezone.utc)
        
        # Timestamp should remain unchanged
        assert token.created_at == original_time
    
    def test_multiple_generated_tokens_are_unique(self):
        """Test that multiple generated tokens are unique."""
        # Act
        tokens = [EmailConfirmationToken.generate() for _ in range(10)]
        token_values = [token.value for token in tokens]
        
        # Assert
        assert len(set(token_values)) == 10  # All tokens should be unique
    
    def test_token_with_uppercase_hex(self):
        """Test that uppercase hex characters are accepted."""
        # Arrange
        uppercase_token = "ABCDEF" * 10 + "1234"  # 60 + 4 = 64 characters
        
        # Act
        token = EmailConfirmationToken(uppercase_token)
        
        # Assert
        assert token.value == uppercase_token
    
    def test_token_with_mixed_case_hex(self):
        """Test that mixed case hex characters are accepted."""
        # Arrange
        mixed_token = "aBcDeF" * 10 + "1234"  # 60 + 4 = 64 characters
        
        # Act
        token = EmailConfirmationToken(mixed_token)
        
        # Assert
        assert token.value == mixed_token 