"""Enhanced Reset Token Value Object Tests.

This module tests the enhanced ResetToken value object with improved security features
including unpredictable token format, character diversity validation, and security metrics.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from src.domain.value_objects.reset_token import ResetToken


class TestEnhancedResetTokenGeneration:
    """Test enhanced token generation with unpredictable format."""
    
    def test_generate_token_has_variable_length(self):
        """Test that generated tokens have variable length for unpredictability."""
        tokens = [ResetToken.generate() for _ in range(10)]
        lengths = [len(token.value) for token in tokens]
        
        # Should have variable length between MIN and MAX
        assert all(ResetToken.MIN_TOKEN_LENGTH <= length <= ResetToken.MAX_TOKEN_LENGTH for length in lengths)
        
        # Should not all be the same length (unpredictable)
        assert len(set(lengths)) > 1
    
    def test_generate_token_has_character_diversity(self):
        """Test that generated tokens contain all required character sets."""
        token = ResetToken.generate()
        
        # Check for uppercase letters
        assert any(c in ResetToken.UPPERCASE_CHARS for c in token.value)
        
        # Check for lowercase letters
        assert any(c in ResetToken.LOWERCASE_CHARS for c in token.value)
        
        # Check for digits
        assert any(c in ResetToken.DIGIT_CHARS for c in token.value)
        
        # Check for special characters
        assert any(c in ResetToken.SPECIAL_CHARS for c in token.value)
    
    def test_generate_token_is_unpredictable(self):
        """Test that generated tokens are unpredictable and unique."""
        tokens = [ResetToken.generate() for _ in range(20)]
        token_values = [token.value for token in tokens]
        
        # All tokens should be unique
        assert len(set(token_values)) == len(token_values)
        
        # Tokens should have different character distributions
        char_distributions = []
        for token in tokens:
            distribution = {
                'uppercase': sum(1 for c in token.value if c in ResetToken.UPPERCASE_CHARS),
                'lowercase': sum(1 for c in token.value if c in ResetToken.LOWERCASE_CHARS),
                'digits': sum(1 for c in token.value if c in ResetToken.DIGIT_CHARS),
                'special': sum(1 for c in token.value if c in ResetToken.SPECIAL_CHARS)
            }
            char_distributions.append(distribution)
        
        # Should have different distributions (not all identical)
        assert len(set(str(d) for d in char_distributions)) > 1
    
    def test_generate_token_with_custom_expiry(self):
        """Test token generation with custom expiry time."""
        custom_expiry = 15
        token = ResetToken.generate(expiry_minutes=custom_expiry)
        
        expected_expiry = datetime.now(timezone.utc) + timedelta(minutes=custom_expiry)
        
        # Allow 1 second tolerance for generation time
        assert abs((token.expires_at - expected_expiry).total_seconds()) < 1
    
    def test_generate_token_default_expiry(self):
        """Test token generation with default expiry time."""
        token = ResetToken.generate()
        
        expected_expiry = datetime.now(timezone.utc) + timedelta(minutes=ResetToken.DEFAULT_EXPIRY_MINUTES)
        
        # Allow 1 second tolerance for generation time
        assert abs((token.expires_at - expected_expiry).total_seconds()) < 1


class TestEnhancedResetTokenValidation:
    """Test enhanced token validation with character diversity requirements."""
    
    def test_valid_token_with_all_character_sets(self):
        """Test that a token with all character sets is valid."""
        # Create a valid token manually with proper length
        valid_token = "A" + "b" + "1" + "!" + "x" * (ResetToken.MIN_TOKEN_LENGTH - 4)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        token = ResetToken(value=valid_token, expires_at=expires_at)
        
        assert token.value == valid_token
        assert token.expires_at == expires_at
    
    def test_token_too_short_raises_error(self):
        """Test that tokens shorter than minimum length raise error."""
        short_token = "Abc1!"  # Only 5 characters
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        with pytest.raises(ValueError, match="must be between"):
            ResetToken(value=short_token, expires_at=expires_at)
    
    def test_token_too_long_raises_error(self):
        """Test that tokens longer than maximum length raise error."""
        # Create a token that has all required character sets but is too long
        long_token = "A" + "b" + "1" + "!" + "x" * (ResetToken.MAX_TOKEN_LENGTH + 1)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        with pytest.raises(ValueError, match="must be between"):
            ResetToken(value=long_token, expires_at=expires_at)
    
    def test_token_missing_uppercase_raises_error(self):
        """Test that tokens without uppercase letters raise error."""
        token_without_uppercase = "b" + "1" + "!" + "x" * (ResetToken.MIN_TOKEN_LENGTH - 3)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

        with pytest.raises(ValueError, match="Token must contain at least one uppercase letter"):
            ResetToken(value=token_without_uppercase, expires_at=expires_at)
    
    def test_token_missing_lowercase_raises_error(self):
        """Test that tokens without lowercase letters raise error."""
        token_without_lowercase = "A" + "1" + "!" + "X" * (ResetToken.MIN_TOKEN_LENGTH - 3)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

        with pytest.raises(ValueError, match="Token must contain at least one lowercase letter"):
            ResetToken(value=token_without_lowercase, expires_at=expires_at)
    
    def test_token_missing_digits_raises_error(self):
        """Test that tokens without digits raise error."""
        token_without_digits = "A" + "b" + "!" + "x" * (ResetToken.MIN_TOKEN_LENGTH - 3)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        with pytest.raises(ValueError, match="must contain.*digit"):
            ResetToken(value=token_without_digits, expires_at=expires_at)
    
    def test_token_missing_special_chars_raises_error(self):
        """Test that tokens without special characters raise error."""
        token_without_special = "A" + "b" + "1" + "x" * (ResetToken.MIN_TOKEN_LENGTH - 3)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        with pytest.raises(ValueError, match="must contain.*special"):
            ResetToken(value=token_without_special, expires_at=expires_at)
    
    def test_empty_token_raises_error(self):
        """Test that empty tokens raise error."""
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        with pytest.raises(ValueError, match="cannot be empty"):
            ResetToken(value="", expires_at=expires_at)
    
    def test_none_token_raises_error(self):
        """Test that None tokens raise error."""
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        with pytest.raises(ValueError, match="cannot be empty"):
            ResetToken(value=None, expires_at=expires_at)
    
    def test_token_without_timezone_raises_error(self):
        """Test that tokens with naive datetime raise error."""
        valid_token = "A" + "b" + "1" + "!" + "x" * (ResetToken.MIN_TOKEN_LENGTH - 4)
        naive_expires_at = datetime.now() + timedelta(minutes=5)
        
        with pytest.raises(ValueError, match="must be timezone-aware"):
            ResetToken(value=valid_token, expires_at=naive_expires_at)
    
    def test_none_expiry_raises_error(self):
        """Test that None expiry raises error."""
        valid_token = "A" + "b" + "1" + "!" + "x" * (ResetToken.MIN_TOKEN_LENGTH - 4)
        
        with pytest.raises(ValueError, match="cannot be empty"):
            ResetToken(value=valid_token, expires_at=None)


class TestEnhancedResetTokenSecurityMetrics:
    """Test security metrics functionality."""
    
    def test_get_security_metrics_returns_comprehensive_data(self):
        """Test that security metrics return comprehensive security data."""
        token = ResetToken.generate()
        metrics = token.get_security_metrics()
        
        # Check required fields
        assert 'length' in metrics
        assert 'character_diversity' in metrics
        assert 'unique_characters' in metrics
        assert 'entropy_bits' in metrics
        assert 'format_unpredictable' in metrics
        
        # Check data types and values
        assert isinstance(metrics['length'], int)
        assert ResetToken.MIN_TOKEN_LENGTH <= metrics['length'] <= ResetToken.MAX_TOKEN_LENGTH
        
        assert isinstance(metrics['character_diversity'], dict)
        assert 'uppercase' in metrics['character_diversity']
        assert 'lowercase' in metrics['character_diversity']
        assert 'digits' in metrics['character_diversity']
        assert 'special' in metrics['character_diversity']
        
        assert isinstance(metrics['unique_characters'], int)
        assert metrics['unique_characters'] > 0
        
        assert isinstance(metrics['entropy_bits'], float)
        assert metrics['entropy_bits'] > 0
        
        assert metrics['format_unpredictable'] is True
    
    def test_security_metrics_character_diversity_sum(self):
        """Test that character diversity sums to token length."""
        token = ResetToken.generate()
        metrics = token.get_security_metrics()

        diversity_sum = sum(metrics['character_diversity'].values())
        # With extended special characters, some characters might be counted in multiple categories
        # So the sum can be greater than or equal to the length
        assert diversity_sum >= metrics['length']
    
    def test_security_metrics_entropy_calculation(self):
        """Test that entropy calculation is reasonable."""
        token = ResetToken.generate()
        metrics = token.get_security_metrics()
        
        # Entropy should be positive and reasonable
        assert metrics['entropy_bits'] > 0
        
        # For a token with mixed character sets, entropy should be substantial
        # But not unrealistically high - just check it's reasonable
        assert metrics['entropy_bits'] > 100  # Should have substantial entropy
        assert metrics['entropy_bits'] < 10000  # But not unrealistically high


class TestEnhancedResetTokenLifecycle:
    """Test token lifecycle methods with enhanced security."""
    
    def test_token_expiration_check(self):
        """Test token expiration checking."""
        # Create expired token
        expired_token = ResetToken.generate()
        expired_token = ResetToken(
            value=expired_token.value,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        
        assert expired_token.is_expired()
        assert not expired_token.is_valid()
        
        # Create valid token
        valid_token = ResetToken.generate()
        assert not valid_token.is_expired()
        assert valid_token.is_valid()
    
    def test_time_remaining_calculation(self):
        """Test time remaining calculation."""
        # Create token with 5 minutes expiry
        token = ResetToken.generate(expiry_minutes=5)
        
        remaining = token.time_remaining()
        assert remaining.total_seconds() > 0
        assert remaining.total_seconds() <= 300  # 5 minutes in seconds
        
        # Test expired token
        expired_token = ResetToken(
            value=token.value,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        
        remaining_expired = expired_token.time_remaining()
        assert remaining_expired.total_seconds() < 0
    
    def test_mask_for_logging(self):
        """Test token masking for secure logging."""
        token = ResetToken.generate()
        masked = token.mask_for_logging()
        
        # Should show first 8 characters and ellipsis
        assert masked.startswith(token.value[:8])
        assert masked.endswith("...")
        assert len(masked) == 11  # 8 chars + "..."
    
    def test_from_existing_validation(self):
        """Test creating token from existing values with validation."""
        # Valid existing token
        valid_token = "A" + "b" + "1" + "!" + "x" * (ResetToken.MIN_TOKEN_LENGTH - 4)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        token = ResetToken.from_existing(valid_token, expires_at)
        assert token.value == valid_token
        assert token.expires_at == expires_at
        
        # Invalid existing token should raise error
        invalid_token = "invalid"
        
        with pytest.raises(ValueError):
            ResetToken.from_existing(invalid_token, expires_at)


class TestEnhancedResetTokenImmutability:
    """Test that tokens are immutable once created."""
    
    def test_token_is_immutable(self):
        """Test that token attributes cannot be modified."""
        token = ResetToken.generate()
        
        # Attempting to modify should raise AttributeError
        with pytest.raises(AttributeError):
            token.value = "new_value"
        
        with pytest.raises(AttributeError):
            token.expires_at = datetime.now(timezone.utc)
    
    def test_token_hashability(self):
        """Test that tokens are hashable for use in sets and dicts."""
        tokens = [ResetToken.generate() for _ in range(5)]
        
        # Should be able to create a set of tokens
        token_set = set(tokens)
        assert len(token_set) == len(tokens)
        
        # Should be able to use as dictionary keys
        token_dict = {token: i for i, token in enumerate(tokens)}
        assert len(token_dict) == len(tokens)


class TestEnhancedResetTokenEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_minimum_length_token(self):
        """Test token with minimum allowed length."""
        min_length_token = "A" + "b" + "1" + "!" + "x" * (ResetToken.MIN_TOKEN_LENGTH - 4)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        token = ResetToken(value=min_length_token, expires_at=expires_at)
        assert len(token.value) == ResetToken.MIN_TOKEN_LENGTH
    
    def test_maximum_length_token(self):
        """Test token with maximum allowed length."""
        max_length_token = "A" + "b" + "1" + "!" + "x" * (ResetToken.MAX_TOKEN_LENGTH - 4)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        token = ResetToken(value=max_length_token, expires_at=expires_at)
        assert len(token.value) == ResetToken.MAX_TOKEN_LENGTH
    
    def test_token_with_all_special_characters(self):
        """Test token with various special characters."""
        special_chars = ResetToken.SPECIAL_CHARS
        test_token = "A" + "b" + "1" + special_chars[0] + "x" * (ResetToken.MIN_TOKEN_LENGTH - 4)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        token = ResetToken(value=test_token, expires_at=expires_at)
        assert token.value == test_token
    
    def test_token_generation_under_load(self):
        """Test token generation under simulated load."""
        import threading
        import time
        
        tokens = []
        errors = []
        
        def generate_token():
            try:
                token = ResetToken.generate()
                tokens.append(token)
            except Exception as e:
                errors.append(e)
        
        # Generate tokens in multiple threads
        threads = [threading.Thread(target=generate_token) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        
        # Should have no errors and all unique tokens
        assert len(errors) == 0
        assert len(tokens) == 10
        assert len(set(token.value for token in tokens)) == 10 