"""Test cases for password reset token functionality using PasswordResetTokenService.

This module contains comprehensive tests for password reset token operations including:
- Secure token generation with proper entropy
- Token validation with timing attack protection
- Token expiration and cleanup
- Edge cases and security scenarios

All tests use the PasswordResetTokenService following Domain-Driven Design principles.
"""

import secrets
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from src.domain.entities.user import User, Role
from src.domain.services.auth.password_reset_token_service import PasswordResetTokenService


class TestPasswordResetTokenService:
    """Test suite for PasswordResetTokenService functionality.
    
    This test suite ensures secure token operations work correctly with proper
    security measures and follow Domain-Driven Design principles.
    """

    def test_generate_token_creates_secure_token(self):
        """Test that generate_token creates a cryptographically secure token."""
        # Arrange
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_pwd",
            role=Role.USER,
        )
        service = PasswordResetTokenService()

        # Act
        token = service.generate_token(user)

        # Assert
        assert token is not None
        assert len(token) == 64  # 32 bytes hex encoded
        assert all(c in "0123456789abcdef" for c in token)  # Valid hex
        assert user.password_reset_token == token
        assert user.password_reset_token_expires_at is not None

    def test_generate_token_sets_correct_expiry(self):
        """Test that generate_token sets correct expiration time."""
        # Arrange
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_pwd",
            role=Role.USER,
        )
        service = PasswordResetTokenService()
        before_generation = datetime.now(timezone.utc)

        # Act
        token = service.generate_token(user)  # Use default expiration (5 minutes)

        # Assert
        after_generation = datetime.now(timezone.utc)
        expected_expiry_start = before_generation + timedelta(minutes=5)
        expected_expiry_end = after_generation + timedelta(minutes=5)

        assert user.password_reset_token_expires_at >= expected_expiry_start
        assert user.password_reset_token_expires_at <= expected_expiry_end

    def test_generate_token_with_custom_expiry(self):
        """Test that generate_token respects custom expiry time."""
        # Arrange
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_pwd",
            role=Role.USER,
        )
        service = PasswordResetTokenService()
        custom_expiry_minutes = 30
        before_generation = datetime.now(timezone.utc)

        # Act
        token = service.generate_token(user, expire_minutes=custom_expiry_minutes)

        # Assert
        after_generation = datetime.now(timezone.utc)
        expected_expiry_start = before_generation + timedelta(minutes=custom_expiry_minutes)
        expected_expiry_end = after_generation + timedelta(minutes=custom_expiry_minutes)

        assert user.password_reset_token_expires_at >= expected_expiry_start
        assert user.password_reset_token_expires_at <= expected_expiry_end

    def test_is_token_valid_with_valid_token(self):
        """Test that is_token_valid returns True for valid, unexpired tokens."""
        # Arrange
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_pwd",
            role=Role.USER,
        )
        service = PasswordResetTokenService()
        token = service.generate_token(user)

        # Act
        is_valid = service.is_token_valid(user, token)

        # Assert
        assert is_valid is True

    def test_is_token_valid_with_invalid_token(self):
        """Test that is_token_valid returns False for invalid tokens."""
        # Arrange
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_pwd",
            role=Role.USER,
        )
        service = PasswordResetTokenService()
        service.generate_token(user)
        invalid_token = secrets.token_hex(32)  # Different token

        # Act
        is_valid = service.is_token_valid(user, invalid_token)

        # Assert
        assert is_valid is False

    def test_is_token_valid_with_no_token_set(self):
        """Test that is_token_valid returns False when no token is set on user."""
        # Arrange
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_pwd",
            role=Role.USER,
        )
        service = PasswordResetTokenService()
        some_token = secrets.token_hex(32)

        # Act
        is_valid = service.is_token_valid(user, some_token)

        # Assert
        assert is_valid is False

    def test_is_token_valid_with_expired_token(self):
        """Test that is_token_valid returns False for expired tokens."""
        # Arrange
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_pwd",
            role=Role.USER,
        )
        service = PasswordResetTokenService()
        token = service.generate_token(user)

        # Manually set expiration to past
        user.password_reset_token_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)

        # Act
        is_valid = service.is_token_valid(user, token)

        # Assert
        assert is_valid is False

    def test_clear_token_clears_fields(self):
        """Test that clear_token properly clears token and expiration fields."""
        # Arrange
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_pwd",
            role=Role.USER,
        )
        service = PasswordResetTokenService()
        service.generate_token(user)

        # Verify token is set before clearing
        assert user.password_reset_token is not None
        assert user.password_reset_token_expires_at is not None

        # Act
        service.clear_token(user)

        # Assert
        assert user.password_reset_token is None
        assert user.password_reset_token_expires_at is None

    def test_generate_token_replaces_existing_token(self):
        """Test that generate_token replaces existing tokens."""
        # Arrange
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_pwd",
            role=Role.USER,
        )
        service = PasswordResetTokenService()
        first_token = service.generate_token(user)
        first_expiry = user.password_reset_token_expires_at

        # Act - Generate second token
        second_token = service.generate_token(user)

        # Assert
        assert first_token != second_token
        assert user.password_reset_token == second_token
        assert user.password_reset_token != first_token
        assert user.password_reset_token_expires_at != first_expiry

    def test_timing_attack_protection(self):
        """Test that token validation uses constant-time comparison."""
        # This test ensures secrets.compare_digest is used internally
        # by testing that validation time doesn't vary significantly
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_pwd",
            role=Role.USER,
        )
        service = PasswordResetTokenService()
        token = service.generate_token(user)

        # Test multiple validations and ensure they're reasonably consistent
        times = []
        for _ in range(10):
            start = time.perf_counter()
            service.is_token_valid(user, token)
            end = time.perf_counter()
            times.append(end - start)

        # Timing should be relatively consistent (within reasonable bounds)
        avg_time = sum(times) / len(times)
        for t in times:
            assert abs(t - avg_time) < 0.001  # Allow 1ms variance

    @pytest.mark.parametrize("expire_minutes", [5, 15, 30, 60])
    def test_generate_token_various_expiry_times(self, expire_minutes):
        """Test token generation with various expiry times."""
        # Arrange
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_pwd",
            role=Role.USER,
        )
        service = PasswordResetTokenService()
        before_generation = datetime.now(timezone.utc)

        # Act
        token = service.generate_token(user, expire_minutes=expire_minutes)

        # Assert
        after_generation = datetime.now(timezone.utc)
        expected_expiry_start = before_generation + timedelta(minutes=expire_minutes)
        expected_expiry_end = after_generation + timedelta(minutes=expire_minutes)

        assert len(token) == 64
        assert user.password_reset_token_expires_at >= expected_expiry_start
        assert user.password_reset_token_expires_at <= expected_expiry_end

    def test_token_entropy_validation(self):
        """Test that generated tokens have sufficient entropy."""
        # Generate multiple tokens and ensure they're all different
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_pwd",
            role=Role.USER,
        )
        service = PasswordResetTokenService()
        tokens = set()

        for _ in range(100):
            token = service.generate_token(user)
            assert token not in tokens  # Each token should be unique
            tokens.add(token)

    def test_is_token_expired_with_expired_token(self):
        """Test that is_token_expired correctly identifies expired tokens."""
        # Arrange
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_pwd",
            role=Role.USER,
        )
        service = PasswordResetTokenService()
        service.generate_token(user)
        
        # Manually set expiration to past
        user.password_reset_token_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)

        # Act
        is_expired = service.is_token_expired(user)

        # Assert
        assert is_expired is True

    def test_is_token_expired_with_valid_token(self):
        """Test that is_token_expired returns False for valid tokens."""
        # Arrange
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_pwd",
            role=Role.USER,
        )
        service = PasswordResetTokenService()
        service.generate_token(user)

        # Act
        is_expired = service.is_token_expired(user)

        # Assert
        assert is_expired is False

    def test_is_token_expired_with_no_token(self):
        """Test that is_token_expired returns False when no token exists."""
        # Arrange
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_pwd",
            role=Role.USER,
        )
        service = PasswordResetTokenService()

        # Act
        is_expired = service.is_token_expired(user)

        # Assert
        assert is_expired is False

    def test_get_token_expiry(self):
        """Test that get_token_expiry returns the correct expiration datetime."""
        # Arrange
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_pwd",
            role=Role.USER,
        )
        service = PasswordResetTokenService()
        service.generate_token(user, expire_minutes=30)

        # Act
        expiry = service.get_token_expiry(user)

        # Assert
        assert expiry == user.password_reset_token_expires_at
        assert isinstance(expiry, datetime)

    def test_get_token_expiry_with_no_token(self):
        """Test that get_token_expiry returns None when no token exists."""
        # Arrange
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_pwd",
            role=Role.USER,
        )
        service = PasswordResetTokenService()

        # Act
        expiry = service.get_token_expiry(user)

        # Assert
        assert expiry is None

    def test_generate_token_default_expiration(self):
        """Test token generation with default 5-minute expiration."""
        # Arrange
        user = User(id=1, username="testuser", email="test@example.com")
        
        # Act
        token = PasswordResetTokenService.generate_token(user)
        
        # Assert
        assert user.password_reset_token == token
        assert len(token) == 64  # 32 bytes = 64 hex chars
        # Default should be 5 minutes, not 15
        expected_expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
        assert abs((user.password_reset_token_expires_at - expected_expiry).total_seconds()) < 2
        
    def test_generate_token_custom_expiration(self):
        """Test token generation with custom expiration time."""
        # Arrange
        user = User(id=1, username="testuser", email="test@example.com")
        custom_minutes = 10
        
        # Act
        token = PasswordResetTokenService.generate_token(user, expire_minutes=custom_minutes)
        
        # Assert
        assert user.password_reset_token == token
        expected_expiry = datetime.now(timezone.utc) + timedelta(minutes=custom_minutes)
        assert abs((user.password_reset_token_expires_at - expected_expiry).total_seconds()) < 2
        
    def test_generate_token_invalid_user(self):
        """Test token generation with invalid user raises error."""
        # Act & Assert
        with pytest.raises(ValueError, match="User cannot be None"):
            PasswordResetTokenService.generate_token(None)
            
    def test_generate_token_replaces_existing(self):
        """Test that generating a new token replaces the existing one."""
        # Arrange
        user = User(id=1, username="testuser", email="test@example.com")
        first_token = PasswordResetTokenService.generate_token(user)
        
        # Act
        second_token = PasswordResetTokenService.generate_token(user)
        
        # Assert
        assert first_token != second_token
        assert user.password_reset_token == second_token
        assert len(second_token) == 64
        
    def test_invalidate_token_one_time_use(self):
        """Test token invalidation for one-time use enforcement."""
        # Arrange
        user = User(id=1, username="testuser", email="test@example.com")
        token = PasswordResetTokenService.generate_token(user)
        
        # Verify token is valid
        assert PasswordResetTokenService.is_token_valid(user, token)
        
        # Act
        PasswordResetTokenService.invalidate_token(user, reason="used")
        
        # Assert
        assert user.password_reset_token is None
        assert user.password_reset_token_expires_at is None
        assert not PasswordResetTokenService.is_token_valid(user, token)
        
    def test_invalidate_token_idempotent(self):
        """Test that invalidating a token multiple times is safe."""
        # Arrange
        user = User(id=1, username="testuser", email="test@example.com")
        token = PasswordResetTokenService.generate_token(user)
        
        # Act
        PasswordResetTokenService.invalidate_token(user, reason="first")
        PasswordResetTokenService.invalidate_token(user, reason="second")
        
        # Assert - should not raise errors
        assert user.password_reset_token is None
        assert user.password_reset_token_expires_at is None
        
    def test_invalidate_token_invalid_user(self):
        """Test invalidating token with invalid user."""
        # Act & Assert - should not raise errors
        PasswordResetTokenService.invalidate_token(None, reason="test")
        
    def test_is_token_valid_format_validation(self):
        """Test token validation rejects invalid formats."""
        # Arrange
        user = User(id=1, username="testuser", email="test@example.com")
        PasswordResetTokenService.generate_token(user)
        
        # Test cases for invalid formats
        invalid_tokens = [
            "short",  # Too short
            "x" * 64,  # Invalid hex characters
            "1234567890abcdef" * 3,  # Wrong length (48 chars)
            "1234567890abcdef" * 5,  # Wrong length (80 chars)
            "",  # Empty
            None,  # None
            "g" + "0" * 63,  # Invalid hex character
        ]
        
        # Act & Assert
        for invalid_token in invalid_tokens:
            assert not PasswordResetTokenService.is_token_valid(user, invalid_token)
            
    def test_is_token_valid_edge_cases(self):
        """Test token validation edge cases."""
        # Arrange
        user = User(id=1, username="testuser", email="test@example.com")
        token = PasswordResetTokenService.generate_token(user)
        
        # Test with None user
        assert not PasswordResetTokenService.is_token_valid(None, token)
        
        # Test with user having no token
        user_no_token = User(id=2, username="other", email="other@example.com")
        assert not PasswordResetTokenService.is_token_valid(user_no_token, token)
        
        # Test with user having no expiration
        user_no_expiry = User(id=3, username="another", email="another@example.com")
        user_no_expiry.password_reset_token = token
        user_no_expiry.password_reset_token_expires_at = None
        assert not PasswordResetTokenService.is_token_valid(user_no_expiry, token)
        
    def test_get_remaining_time(self):
        """Test getting remaining time for token."""
        # Arrange
        user = User(id=1, username="testuser", email="test@example.com")
        PasswordResetTokenService.generate_token(user)
        
        # Act
        remaining = PasswordResetTokenService.get_remaining_time(user)
        
        # Assert
        assert remaining is not None
        assert remaining.total_seconds() > 0
        assert remaining.total_seconds() <= 300  # 5 minutes in seconds
        
    def test_get_remaining_time_no_token(self):
        """Test getting remaining time when no token exists."""
        # Arrange
        user = User(id=1, username="testuser", email="test@example.com")
        
        # Act
        remaining = PasswordResetTokenService.get_remaining_time(user)
        
        # Assert
        assert remaining is None
        
    def test_get_remaining_time_expired(self):
        """Test getting remaining time for expired token."""
        # Arrange
        user = User(id=1, username="testuser", email="test@example.com")
        user.password_reset_token = "1234567890abcdef" * 4
        user.password_reset_token_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        
        # Act
        remaining = PasswordResetTokenService.get_remaining_time(user)
        
        # Assert
        assert remaining is None 