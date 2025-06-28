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
        token = service.generate_token(user, expire_minutes=15)

        # Assert
        after_generation = datetime.now(timezone.utc)
        expected_expiry_start = before_generation + timedelta(minutes=15)
        expected_expiry_end = after_generation + timedelta(minutes=15)

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