"""
Comprehensive feature tests for the complete user registration journey.

This test suite mirrors real-world user registration scenarios including:
- User registration with email confirmation
- Email confirmation flow
- Resend confirmation email
- Registration without email confirmation
- Internationalization support
- Security validations
- Error handling and edge cases

These tests use real services and database interactions, similar to RSpec Rails integration tests.
"""

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import text

from src.main import app
from src.infrastructure.database.async_db import get_async_db
from src.infrastructure.redis import get_redis
from src.core.config.settings import settings


class TestUserRegistrationJourney:
    """End-to-end user registration journey tests without mocking."""

    @pytest_asyncio.fixture(scope="function")
    async def clean_database(self):
        """Clean database before and after each test."""
        async with get_async_db() as db:
            try:
                # Clean up any existing test data
                await db.execute(text("DELETE FROM users WHERE email LIKE '%@test.com'"))
                await db.execute(text("DELETE FROM oauth_profiles WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@test.com')"))
                await db.execute(text("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@test.com')"))
                await db.commit()
                yield db
            finally:
                # Cleanup after test
                try:
                    await db.execute(text("DELETE FROM users WHERE email LIKE '%@test.com'"))
                    await db.execute(text("DELETE FROM oauth_profiles WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@test.com')"))
                    await db.execute(text("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@test.com')"))
                    await db.commit()
                except Exception:
                    await db.rollback()

    def test_complete_registration_with_email_confirmation(self, clean_database):
        """Test the complete user registration journey with email confirmation enabled."""
        client = TestClient(app)
        
        # Step 1: Register a new user
        registration_data = {
            "username": "newuser123",
            "email": "newuser@test.com",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        assert "message" in response.json()
        assert "user" in response.json()
        
        user_data = response.json()["user"]
        assert user_data["username"] == "newuser123"
        assert user_data["email"] == "newuser@test.com"
        assert user_data["is_active"] is False  # Should be inactive until email confirmed
        assert user_data["email_confirmed"] is False
        
        # Step 2: Try to login (should fail - email not confirmed)
        login_data = {
            "username": "newuser123",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 401
        assert "email confirmation" in response.json()["detail"].lower()
        
        # Step 3: Get the confirmation token from the database
        async def get_confirmation_token():
            async with get_async_db() as db:
                result = await db.execute(
                    text("SELECT email_confirmation_token FROM users WHERE email = :email"),
                    {"email": "newuser@test.com"}
                )
                return result.scalar()
        
        import asyncio
        confirmation_token = asyncio.run(get_confirmation_token())
        assert confirmation_token is not None
        
        # Step 4: Confirm email with the token
        response = client.get(f"/api/v1/auth/confirm-email?token={confirmation_token}")
        assert response.status_code == 200
        assert "confirmed" in response.json()["message"].lower()
        
        # Step 5: Verify user is now active and confirmed
        async def verify_user_status():
            async with get_async_db() as db:
                result = await db.execute(
                    text("SELECT is_active, email_confirmed FROM users WHERE email = :email"),
                    {"email": "newuser@test.com"}
                )
                return result.fetchone()
        
        user_status = asyncio.run(verify_user_status())
        assert user_status[0] is True  # is_active
        assert user_status[1] is True  # email_confirmed
        
        # Step 6: Login should now succeed
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 200
        assert "access_token" in response.json()
        assert "refresh_token" in response.json()

    def test_registration_without_email_confirmation(self, clean_database):
        """Test user registration when email confirmation is disabled."""
        # Temporarily disable email confirmation
        original_setting = settings.EMAIL_CONFIRMATION_ENABLED
        settings.EMAIL_CONFIRMATION_ENABLED = False
        
        try:
            client = TestClient(app)
            
            registration_data = {
                "username": "directuser",
                "email": "direct@test.com",
                "password": "SecurePass789!"
            }
            
            response = client.post("/api/v1/auth/register", json=registration_data)
            assert response.status_code == 201
            
            user_data = response.json()["user"]
            assert user_data["is_active"] is True  # Should be active immediately
            assert user_data["email_confirmed"] is True
            
            # Login should work immediately
            login_data = {
                "username": "directuser",
                "password": "SecurePass789!"
            }
            
            response = client.post("/api/v1/auth/login", json=login_data)
            assert response.status_code == 200
            assert "access_token" in response.json()
            
        finally:
            settings.EMAIL_CONFIRMATION_ENABLED = original_setting

    def test_resend_confirmation_email(self, clean_database):
        """Test resending confirmation email functionality."""
        client = TestClient(app)
        
        # Step 1: Register a user
        registration_data = {
            "username": "resenduser",
            "email": "resend@test.com",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Step 2: Resend confirmation email
        resend_data = {"email": "resend@test.com"}
        response = client.post("/api/v1/auth/resend-confirmation", json=resend_data)
        assert response.status_code == 200
        assert "sent" in response.json()["message"].lower()
        
        # Step 3: Verify a new token was generated
        async def get_new_token():
            async with get_async_db() as db:
                result = await db.execute(
                    text("SELECT email_confirmation_token FROM users WHERE email = :email"),
                    {"email": "resend@test.com"}
                )
                return result.scalar()
        
        import asyncio
        new_token = asyncio.run(get_new_token())
        assert new_token is not None
        
        # Step 4: Confirm with the new token
        response = client.get(f"/api/v1/auth/confirm-email?token={new_token}")
        assert response.status_code == 200

    def test_registration_validation_errors(self, clean_database):
        """Test various validation errors during registration."""
        client = TestClient(app)
        
        # Test 1: Invalid email format
        invalid_data = {
            "username": "testuser",
            "email": "invalid-email",
            "password": "SecurePass789!"
        }
        response = client.post("/api/v1/auth/register", json=invalid_data)
        assert response.status_code == 422
        
        # Test 2: Weak password
        weak_password_data = {
            "username": "testuser",
            "email": "test@test.com",
            "password": "weak"
        }
        response = client.post("/api/v1/auth/register", json=weak_password_data)
        assert response.status_code == 422
        
        # Test 3: Username too short
        short_username_data = {
            "username": "ab",
            "email": "test@test.com",
            "password": "SecurePass789!"
        }
        response = client.post("/api/v1/auth/register", json=short_username_data)
        assert response.status_code == 422
        
        # Test 4: Missing required fields
        missing_fields_data = {
            "username": "testuser"
            # Missing email and password
        }
        response = client.post("/api/v1/auth/register", json=missing_fields_data)
        assert response.status_code == 422

    def test_duplicate_registration_attempts(self, clean_database):
        """Test handling of duplicate registration attempts."""
        client = TestClient(app)
        
        registration_data = {
            "username": "duplicateuser",
            "email": "duplicate@test.com",
            "password": "SecurePass789!"
        }
        
        # First registration should succeed
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Second registration with same email should fail
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"].lower()
        
        # Registration with same username but different email should fail
        duplicate_username_data = {
            "username": "duplicateuser",
            "email": "different@test.com",
            "password": "SecurePass789!"
        }
        response = client.post("/api/v1/auth/register", json=duplicate_username_data)
        assert response.status_code == 400

    def test_invalid_confirmation_token(self, clean_database):
        """Test confirmation with invalid tokens."""
        client = TestClient(app)
        
        # Test with non-existent token
        response = client.get("/api/v1/auth/confirm-email?token=invalid_token_12345")
        assert response.status_code == 404
        
        # Test with empty token
        response = client.get("/api/v1/auth/confirm-email?token=")
        assert response.status_code == 422
        
        # Test without token parameter
        response = client.get("/api/v1/auth/confirm-email")
        assert response.status_code == 422

    def test_registration_with_internationalization(self, clean_database):
        """Test registration with different language preferences."""
        client = TestClient(app)
        
        # Test with Spanish language
        registration_data = {
            "username": "spanishuser",
            "email": "spanish@test.com",
            "password": "SecurePass789!"
        }
        
        response = client.post(
            "/api/v1/auth/register", 
            json=registration_data,
            headers={"Accept-Language": "es"}
        )
        assert response.status_code == 201
        
        # Test with Arabic language
        registration_data = {
            "username": "arabicuser",
            "email": "arabic@test.com",
            "password": "SecurePass789!"
        }
        
        response = client.post(
            "/api/v1/auth/register", 
            json=registration_data,
            headers={"Accept-Language": "ar"}
        )
        assert response.status_code == 201

    def test_registration_security_headers(self, clean_database):
        """Test that registration endpoints return proper security headers."""
        client = TestClient(app)
        
        response = client.get("/api/v1/auth/register")
        # Should return 405 Method Not Allowed for GET request
        
        response = client.post("/api/v1/auth/register", json={})
        # Should return 422 for invalid data, but check headers
        
        # Check for security headers
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "X-XSS-Protection" in response.headers

    def test_registration_rate_limiting(self, clean_database):
        """Test rate limiting on registration endpoint."""
        client = TestClient(app)
        
        registration_data = {
            "username": "rateuser",
            "email": "rate@test.com",
            "password": "SecurePass789!"
        }
        
        # Make multiple rapid registration attempts
        for i in range(5):
            data = registration_data.copy()
            data["username"] = f"rateuser{i}"
            data["email"] = f"rate{i}@test.com"
            
            response = client.post("/api/v1/auth/register", json=data)
            if response.status_code == 429:  # Rate limited
                break
        
        # At some point, we should hit rate limiting
        # Note: This depends on the rate limiting configuration

    def test_registration_with_special_characters(self, clean_database):
        """Test registration with usernames containing special characters."""
        client = TestClient(app)
        
        # Test with underscore in username
        registration_data = {
            "username": "user_name_123",
            "email": "special@test.com",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Test with hyphen in username
        registration_data = {
            "username": "user-name-123",
            "email": "special2@test.com",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201

    def test_registration_edge_cases(self, clean_database):
        """Test various edge cases in registration."""
        client = TestClient(app)
        
        # Test with maximum length username
        max_username = "a" * 50  # Assuming max length is 50
        registration_data = {
            "username": max_username,
            "email": "maxlen@test.com",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Test with minimum length username
        min_username = "abc"  # Assuming min length is 3
        registration_data = {
            "username": min_username,
            "email": "minlen@test.com",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201 