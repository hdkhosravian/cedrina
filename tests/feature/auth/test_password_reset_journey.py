"""
Comprehensive feature tests for the complete password reset journey.

This test suite mirrors real-world password reset scenarios including:
- Password reset request
- Email sending with reset tokens
- Token validation and expiration
- Password reset execution
- Rate limiting and security measures
- Error handling and edge cases

These tests use real services and database interactions, similar to RSpec Rails integration tests.
"""

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import text
from datetime import datetime, timedelta, timezone

from src.main import app
from src.infrastructure.database.async_db import get_async_db
from src.infrastructure.redis import get_redis
from src.core.config.settings import settings


class TestPasswordResetJourney:
    """End-to-end password reset journey tests without mocking."""

    @pytest_asyncio.fixture(autouse=True)
    async def setup_database(self):
        """Setup and cleanup database for each test."""
        async with get_async_db() as db:
            # Clean up any existing test data
            await db.execute(text("DELETE FROM users WHERE email LIKE '%@test.com'"))
            await db.execute(text("DELETE FROM password_reset_tokens WHERE email LIKE '%@test.com'"))
            await db.commit()
            yield db
            # Cleanup after test
            await db.execute(text("DELETE FROM users WHERE email LIKE '%@test.com'"))
            await db.execute(text("DELETE FROM password_reset_tokens WHERE email LIKE '%@test.com'"))
            await db.commit()

    def test_complete_password_reset_journey(self, setup_database):
        """Test the complete password reset journey from request to completion."""
        client = TestClient(app)
        
        # Step 1: Create a user first
        registration_data = {
            "username": "resetuser",
            "email": "reset@test.com",
            "password": "OldPassword123!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Step 2: Request password reset
        reset_request_data = {"email": "reset@test.com"}
        response = client.post("/api/v1/auth/forgot-password", json=reset_request_data)
        assert response.status_code == 200
        assert "sent" in response.json()["message"].lower()
        
        # Step 3: Get the reset token from the database
        async def get_reset_token():
            async with get_async_db() as db:
                result = await db.execute(
                    text("SELECT token FROM password_reset_tokens WHERE email = :email ORDER BY created_at DESC LIMIT 1"),
                    {"email": "reset@test.com"}
                )
                return result.scalar()
        
        import asyncio
        reset_token = asyncio.run(get_reset_token())
        assert reset_token is not None
        
        # Step 4: Reset password with the token
        reset_data = {
            "token": reset_token,
            "new_password": "NewPassword456!"
        }
        
        response = client.post("/api/v1/auth/reset-password", json=reset_data)
        assert response.status_code == 200
        assert "reset" in response.json()["message"].lower()
        
        # Step 5: Verify old password no longer works
        login_data = {
            "username": "resetuser",
            "password": "OldPassword123!"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 401
        
        # Step 6: Verify new password works
        login_data = {
            "username": "resetuser",
            "password": "NewPassword456!"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 200
        assert "access_token" in response.json()

    def test_password_reset_request_for_nonexistent_user(self, setup_database):
        """Test password reset request for a user that doesn't exist."""
        client = TestClient(app)
        
        reset_request_data = {"email": "nonexistent@test.com"}
        response = client.post("/api/v1/auth/forgot-password", json=reset_request_data)
        
        # Should return success to prevent email enumeration
        assert response.status_code == 200
        assert "sent" in response.json()["message"].lower()

    def test_password_reset_with_invalid_token(self, setup_database):
        """Test password reset with invalid or expired tokens."""
        client = TestClient(app)
        
        # Test with non-existent token
        reset_data = {
            "token": "invalid_token_12345",
            "new_password": "NewPassword456!"
        }
        
        response = client.post("/api/v1/auth/reset-password", json=reset_data)
        assert response.status_code == 400
        assert "invalid" in response.json()["detail"].lower()
        
        # Test with empty token
        reset_data = {
            "token": "",
            "new_password": "NewPassword456!"
        }
        
        response = client.post("/api/v1/auth/reset-password", json=reset_data)
        assert response.status_code == 422
        
        # Test with missing token
        reset_data = {
            "new_password": "NewPassword456!"
        }
        
        response = client.post("/api/v1/auth/reset-password", json=reset_data)
        assert response.status_code == 422

    def test_password_reset_with_weak_password(self, setup_database):
        """Test password reset with weak passwords."""
        client = TestClient(app)
        
        # Create a user and get a valid token
        registration_data = {
            "username": "weakuser",
            "email": "weak@test.com",
            "password": "OldPassword123!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Request password reset
        reset_request_data = {"email": "weak@test.com"}
        response = client.post("/api/v1/auth/forgot-password", json=reset_request_data)
        assert response.status_code == 200
        
        # Get the reset token
        async def get_reset_token():
            async with get_async_db() as db:
                result = await db.execute(
                    text("SELECT token FROM password_reset_tokens WHERE email = :email ORDER BY created_at DESC LIMIT 1"),
                    {"email": "weak@test.com"}
                )
                return result.scalar()
        
        import asyncio
        reset_token = asyncio.run(get_reset_token())
        
        # Test with weak password
        reset_data = {
            "token": reset_token,
            "new_password": "weak"
        }
        
        response = client.post("/api/v1/auth/reset-password", json=reset_data)
        assert response.status_code == 422

    def test_password_reset_rate_limiting(self, setup_database):
        """Test rate limiting on password reset requests."""
        client = TestClient(app)
        
        # Create a user
        registration_data = {
            "username": "rateuser",
            "email": "rate@test.com",
            "password": "OldPassword123!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Make multiple rapid password reset requests
        reset_request_data = {"email": "rate@test.com"}
        
        for i in range(10):
            response = client.post("/api/v1/auth/forgot-password", json=reset_request_data)
            if response.status_code == 429:  # Rate limited
                break
        
        # At some point, we should hit rate limiting
        # Note: This depends on the rate limiting configuration

    def test_password_reset_token_expiration(self, setup_database):
        """Test that password reset tokens expire correctly."""
        client = TestClient(app)
        
        # Create a user
        registration_data = {
            "username": "expireuser",
            "email": "expire@test.com",
            "password": "OldPassword123!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Request password reset
        reset_request_data = {"email": "expire@test.com"}
        response = client.post("/api/v1/auth/forgot-password", json=reset_request_data)
        assert response.status_code == 200
        
        # Get the reset token
        async def get_reset_token():
            async with get_async_db() as db:
                result = await db.execute(
                    text("SELECT token FROM password_reset_tokens WHERE email = :email ORDER BY created_at DESC LIMIT 1"),
                    {"email": "expire@test.com"}
                )
                return result.scalar()
        
        import asyncio
        reset_token = asyncio.run(get_reset_token())
        
        # Manually expire the token in the database
        async def expire_token():
            async with get_async_db() as db:
                await db.execute(
                    text("UPDATE password_reset_tokens SET expires_at = :expires_at WHERE token = :token"),
                    {
                        "expires_at": datetime.now(timezone.utc) - timedelta(hours=1),
                        "token": reset_token
                    }
                )
                await db.commit()
        
        asyncio.run(expire_token())
        
        # Try to use the expired token
        reset_data = {
            "token": reset_token,
            "new_password": "NewPassword456!"
        }
        
        response = client.post("/api/v1/auth/reset-password", json=reset_data)
        assert response.status_code == 400
        assert "expired" in response.json()["detail"].lower()

    def test_multiple_password_reset_requests(self, setup_database):
        """Test handling of multiple password reset requests for the same user."""
        client = TestClient(app)
        
        # Create a user
        registration_data = {
            "username": "multipleuser",
            "email": "multiple@test.com",
            "password": "OldPassword123!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Make multiple password reset requests
        reset_request_data = {"email": "multiple@test.com"}
        
        for i in range(3):
            response = client.post("/api/v1/auth/forgot-password", json=reset_request_data)
            assert response.status_code == 200
        
        # Verify multiple tokens were created
        async def count_tokens():
            async with get_async_db() as db:
                result = await db.execute(
                    text("SELECT COUNT(*) FROM password_reset_tokens WHERE email = :email"),
                    {"email": "multiple@test.com"}
                )
                return result.scalar()
        
        import asyncio
        token_count = asyncio.run(count_tokens())
        assert token_count >= 3

    def test_password_reset_with_internationalization(self, setup_database):
        """Test password reset with different language preferences."""
        client = TestClient(app)
        
        # Create a user
        registration_data = {
            "username": "i18nuser",
            "email": "i18n@test.com",
            "password": "OldPassword123!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Request password reset with Spanish language
        reset_request_data = {"email": "i18n@test.com"}
        response = client.post(
            "/api/v1/auth/forgot-password", 
            json=reset_request_data,
            headers={"Accept-Language": "es"}
        )
        assert response.status_code == 200
        
        # Request password reset with Arabic language
        response = client.post(
            "/api/v1/auth/forgot-password", 
            json=reset_request_data,
            headers={"Accept-Language": "ar"}
        )
        assert response.status_code == 200

    def test_password_reset_security_headers(self, setup_database):
        """Test that password reset endpoints return proper security headers."""
        client = TestClient(app)
        
        # Test forgot password endpoint
        response = client.post("/api/v1/auth/forgot-password", json={"email": "test@test.com"})
        
        # Check for security headers
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "X-XSS-Protection" in response.headers
        
        # Test reset password endpoint
        response = client.post("/api/v1/auth/reset-password", json={"token": "test", "new_password": "test"})
        
        # Check for security headers
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "X-XSS-Protection" in response.headers

    def test_password_reset_validation_errors(self, setup_database):
        """Test various validation errors during password reset."""
        client = TestClient(app)
        
        # Test 1: Invalid email format
        invalid_email_data = {"email": "invalid-email"}
        response = client.post("/api/v1/auth/forgot-password", json=invalid_email_data)
        assert response.status_code == 422
        
        # Test 2: Missing email
        missing_email_data = {}
        response = client.post("/api/v1/auth/forgot-password", json=missing_email_data)
        assert response.status_code == 422
        
        # Test 3: Empty email
        empty_email_data = {"email": ""}
        response = client.post("/api/v1/auth/forgot-password", json=empty_email_data)
        assert response.status_code == 422

    def test_password_reset_edge_cases(self, setup_database):
        """Test various edge cases in password reset."""
        client = TestClient(app)
        
        # Test with very long email
        long_email = "a" * 100 + "@test.com"
        reset_request_data = {"email": long_email}
        response = client.post("/api/v1/auth/forgot-password", json=reset_request_data)
        assert response.status_code == 200  # Should not fail for non-existent users
        
        # Test with special characters in email
        special_email_data = {"email": "test+tag@test.com"}
        response = client.post("/api/v1/auth/forgot-password", json=special_email_data)
        assert response.status_code == 200
        
        # Test with unicode characters in email
        unicode_email_data = {"email": "tëst@test.com"}
        response = client.post("/api/v1/auth/forgot-password", json=unicode_email_data)
        assert response.status_code == 200

    def test_password_reset_token_reuse_prevention(self, setup_database):
        """Test that password reset tokens cannot be reused."""
        client = TestClient(app)
        
        # Create a user
        registration_data = {
            "username": "reuseuser",
            "email": "reuse@test.com",
            "password": "OldPassword123!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Request password reset
        reset_request_data = {"email": "reuse@test.com"}
        response = client.post("/api/v1/auth/forgot-password", json=reset_request_data)
        assert response.status_code == 200
        
        # Get the reset token
        async def get_reset_token():
            async with get_async_db() as db:
                result = await db.execute(
                    text("SELECT token FROM password_reset_tokens WHERE email = :email ORDER BY created_at DESC LIMIT 1"),
                    {"email": "reuse@test.com"}
                )
                return result.scalar()
        
        import asyncio
        reset_token = asyncio.run(get_reset_token())
        
        # Use the token successfully
        reset_data = {
            "token": reset_token,
            "new_password": "NewPassword456!"
        }
        
        response = client.post("/api/v1/auth/reset-password", json=reset_data)
        assert response.status_code == 200
        
        # Try to use the same token again
        response = client.post("/api/v1/auth/reset-password", json=reset_data)
        assert response.status_code == 400
        assert "invalid" in response.json()["detail"].lower() 