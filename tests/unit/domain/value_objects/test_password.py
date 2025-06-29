"""Unit tests for Password value objects.

These tests verify that password value objects properly enforce
business rules and security requirements following TDD principles.
"""

import pytest
from unittest.mock import patch
from src.domain.value_objects.password import Password, HashedPassword


class TestPassword:
    """Test cases for Password value object."""
    
    def test_valid_password_creation(self):
        """Test creating a valid password."""
        # Arrange
        valid_password_str = "MyStr0ng#P@ssw0rd"
        
        # Act
        password = Password(value=valid_password_str)
        
        # Assert
        assert password.value == valid_password_str
    
    def test_password_immutability(self):
        """Test that password is immutable."""
        # Arrange
        password = Password(value="MyStr0ng#P@ssw0rd")
        
        # Act & Assert
        with pytest.raises(AttributeError):
            password.value = "new_password"  # type: ignore
    
    def test_password_too_short(self):
        """Test password length validation - too short."""
        # Arrange
        short_password = "Ab1!"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Password must be at least 8 characters long"):
            Password(value=short_password)
    
    def test_password_too_long(self):
        """Test password length validation - too long."""
        # Arrange
        long_password = "A" * 129 + "b1!"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Password must not exceed 128 characters"):
            Password(value=long_password)
    
    def test_password_missing_uppercase(self):
        """Test password validation - missing uppercase letter."""
        # Arrange
        no_upper = "mystr0ng#p@ssw0rd"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Password must contain at least one uppercase letter"):
            Password(value=no_upper)
    
    def test_password_missing_lowercase(self):
        """Test password validation - missing lowercase letter."""
        # Arrange
        no_lower = "MYSTR0NG#P@SSW0RD"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Password must contain at least one lowercase letter"):
            Password(value=no_lower)
    
    def test_password_missing_digit(self):
        """Test password validation - missing digit."""
        # Arrange
        no_digit = "MyStrOng#P@sswOrd"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Password must contain at least one digit"):
            Password(value=no_digit)
    
    def test_password_missing_special_character(self):
        """Test password validation - missing special character."""
        # Arrange
        no_special = "MyStr0ngPassw0rd"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Password must contain at least one special character"):
            Password(value=no_special)
    
    def test_password_empty(self):
        """Test empty password validation."""
        # Act & Assert
        with pytest.raises(ValueError, match="Password cannot be empty"):
            Password(value="")
    
    def test_password_weak_patterns_consecutive_chars(self):
        """Test weak pattern validation - consecutive identical characters."""
        # Arrange
        weak_password = "MyStr0ng#AAA"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Password contains common weak patterns"):
            Password(value=weak_password)
    
    def test_password_weak_patterns_sequential_numbers(self):
        """Test weak pattern validation - sequential numbers."""
        # Arrange
        weak_password = "MyStr0ng#123"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Password contains common weak patterns"):
            Password(value=weak_password)
    
    def test_password_weak_patterns_sequential_letters(self):
        """Test weak pattern validation - sequential letters."""
        # Arrange
        weak_password = "MyStr0ng#abc"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Password contains common weak patterns"):
            Password(value=weak_password)
    
    def test_password_weak_patterns_common_words(self):
        """Test weak pattern validation - common words."""
        # Arrange
        weak_password = "AdminStr0ng#1"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Password contains common weak patterns"):
            Password(value=weak_password)
    
    def test_password_to_hashed(self):
        """Test converting password to hashed password."""
        # Arrange
        password = Password(value="MyStr0ng#P@ssw0rd")
        
        # Act
        hashed = password.to_hashed()
        
        # Assert
        assert isinstance(hashed, HashedPassword)
        assert hashed.value.startswith("$2b$")
        assert len(hashed.value) == 60
    
    def test_password_minimum_valid_length(self):
        """Test minimum valid password length."""
        # Arrange
        min_password = "My8Char!"  # Exactly 8 characters
        
        # Act
        password = Password(value=min_password)
        
        # Assert
        assert password.value == min_password
    
    def test_password_maximum_valid_length(self):
        """Test maximum valid password length."""
        # Arrange
        # Create a 128-char password without weak patterns
        # "MyL0ng#" = 7 chars, "X1Y2" * 30 = 120 chars, "!" = 1 char = 128 total
        max_password = "MyL0ng#" + "X1Y2" * 30 + "!"  # Exactly 128 characters
        
        # Act
        password = Password(value=max_password)
        
        # Assert
        assert password.value == max_password
        assert len(password.value) == 128


class TestHashedPassword:
    """Test cases for HashedPassword value object."""
    
    def test_valid_hashed_password_creation(self):
        """Test creating a valid hashed password."""
        # Arrange
        valid_hash = "$2b$12$PPRH7sTbmZoK3a2RBZNtsuVTB5cI1/Ak5odqP0EWDMgU1eFM7jJhC"
        
        # Act
        hashed = HashedPassword(value=valid_hash)
        
        # Assert
        assert hashed.value == valid_hash
    
    def test_hashed_password_immutability(self):
        """Test that hashed password is immutable."""
        # Arrange
        hashed = HashedPassword(value="$2b$12$PPRH7sTbmZoK3a2RBZNtsuVTB5cI1/Ak5odqP0EWDMgU1eFM7jJhC")
        
        # Act & Assert
        with pytest.raises(AttributeError):
            hashed.value = "new_hash"  # type: ignore
    
    def test_hashed_password_empty(self):
        """Test empty hashed password validation."""
        # Act & Assert
        with pytest.raises(ValueError, match="Hashed password cannot be empty"):
            HashedPassword(value="")
    
    def test_hashed_password_invalid_format(self):
        """Test invalid hashed password format."""
        # Arrange
        invalid_hash = "$2a$12$PPRH7sTbmZoK3a2RBZNtsuVTB5cI1/Ak5odqP0EWDMgU1eFM7jJhC"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid hashed password format"):
            HashedPassword(value=invalid_hash)
    
    def test_hashed_password_invalid_length(self):
        """Test invalid hashed password length."""
        # Arrange
        invalid_hash = "$2b$12$short"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid hashed password length"):
            HashedPassword(value=invalid_hash)
    
    def test_from_plain_password(self):
        """Test creating hashed password from plain password."""
        # Arrange
        plain_password = Password(value="MyStr0ng#P@ssw0rd")
        
        # Act
        hashed = HashedPassword.from_plain_password(plain_password)
        
        # Assert
        assert isinstance(hashed, HashedPassword)
        assert hashed.value.startswith("$2b$")
        assert len(hashed.value) == 60
    
    def test_from_hash(self):
        """Test creating hashed password from existing hash."""
        # Arrange
        existing_hash = "$2b$12$PPRH7sTbmZoK3a2RBZNtsuVTB5cI1/Ak5odqP0EWDMgU1eFM7jJhC"
        
        # Act
        hashed = HashedPassword.from_hash(existing_hash)
        
        # Assert
        assert hashed.value == existing_hash
    
    def test_from_hash_validates_format(self):
        """Test that from_hash validates the hash format."""
        # Arrange
        invalid_hash = "invalid_hash"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid hashed password format"):
            HashedPassword.from_hash(invalid_hash)


class TestPasswordIntegration:
    """Integration test cases for Password and HashedPassword."""
    
    def test_password_hashing_round_trip(self):
        """Test complete password to hashed password workflow."""
        # Arrange
        plain_text = "MyStr0ng#P@ssw0rd"
        
        # Act
        password = Password(value=plain_text)
        hashed = password.to_hashed()
        
        # Assert
        assert password.value == plain_text
        assert isinstance(hashed, HashedPassword)
        assert hashed.value != plain_text
        assert hashed.value.startswith("$2b$")
    
    def test_multiple_password_hashes_are_different(self):
        """Test that hashing the same password produces different hashes."""
        # Arrange
        password1 = Password(value="MyStr0ng#P@ssw0rd")
        password2 = Password(value="MyStr0ng#P@ssw0rd")
        
        # Act
        hashed1 = password1.to_hashed()
        hashed2 = password2.to_hashed()
        
        # Assert
        assert hashed1.value != hashed2.value  # Different salt produces different hashes
        assert hashed1.value.startswith("$2b$")
        assert hashed2.value.startswith("$2b$")
    
    def test_password_security_constants(self):
        """Test password security constraint constants."""
        # Assert
        assert Password.MIN_LENGTH == 8
        assert Password.MAX_LENGTH == 128
        assert Password.REQUIRED_UPPERCASE == 1
        assert Password.REQUIRED_LOWERCASE == 1
        assert Password.REQUIRED_DIGITS == 1
        assert Password.REQUIRED_SPECIAL == 1
        assert isinstance(Password.SPECIAL_CHARS, str)
        assert len(Password.SPECIAL_CHARS) > 0 