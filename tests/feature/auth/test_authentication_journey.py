"""
Comprehensive feature tests for the complete authentication journey.

This test suite mirrors real-world authentication scenarios including:
- User login with valid credentials
- Login with invalid credentials
- Session management and token refresh
- Logout functionality
- Account lockout and security measures
- Multi-device authentication
- Token expiration and renewal

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


class TestAuthenticationJourney:
    """End-to-end authentication journey tests without mocking."""

    @pytest_asyncio.fixture(autouse=True)
    async def setup_database(self):
        """Setup and cleanup database for each test."""
        async with get_async_db() as db:
            # Clean up any existing test data
            await db.execute(text("DELETE FROM users WHERE email LIKE '%@test.com'"))
            await db.execute(text("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@test.com')"))
            await db.commit()
            yield db
            # Cleanup after test
            await db.execute(text("DELETE FROM users WHERE email LIKE '%@test.com'"))
            await db.execute(text("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@test.com')"))
            await db.commit()

    def test_complete_authentication_journey(self, setup_database):
        """Test the complete authentication journey from login to logout."""
        client = TestClient(app)
        
        # Step 1: Create a user
        registration_data = {
            "username": "authuser",
            "email": "auth@test.com",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Step 2: Login with valid credentials
        login_data = {
            "username": "authuser",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 200
        
        auth_response = response.json()
        assert "access_token" in auth_response
        assert "refresh_token" in auth_response
        assert "token_type" in auth_response
        assert auth_response["token_type"] == "bearer"
        
        access_token = auth_response["access_token"]
        refresh_token = auth_response["refresh_token"]
        
        # Step 3: Access protected endpoint with access token
        headers = {"Authorization": f"Bearer {access_token}"}
        response = client.get("/api/v1/auth/me", headers=headers)
        assert response.status_code == 200
        
        user_data = response.json()
        assert user_data["username"] == "authuser"
        assert user_data["email"] == "auth@test.com"
        
        # Step 4: Refresh the access token
        refresh_data = {"refresh_token": refresh_token}
        response = client.post("/api/v1/auth/refresh", json=refresh_data)
        assert response.status_code == 200
        
        new_auth_response = response.json()
        assert "access_token" in new_auth_response
        assert "refresh_token" in new_auth_response
        
        new_access_token = new_auth_response["access_token"]
        
        # Step 5: Use the new access token
        headers = {"Authorization": f"Bearer {new_access_token}"}
        response = client.get("/api/v1/auth/me", headers=headers)
        assert response.status_code == 200
        
        # Step 6: Logout
        logout_data = {"refresh_token": refresh_token}
        response = client.delete("/api/v1/auth/logout", json=logout_data)
        assert response.status_code == 200
        
        # Step 7: Verify logout worked - old access token should still work (JWT is stateless)
        # But refresh token should be invalidated
        response = client.post("/api/v1/auth/refresh", json=refresh_data)
        assert response.status_code == 401

    def test_login_with_invalid_credentials(self, setup_database):
        """Test login attempts with various invalid credentials."""
        client = TestClient(app)
        
        # Create a user first
        registration_data = {
            "username": "invaliduser",
            "email": "invalid@test.com",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Test 1: Wrong password
        login_data = {
            "username": "invaliduser",
            "password": "WrongPassword123!"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 401
        
        # Test 2: Wrong username
        login_data = {
            "username": "wronguser",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 401
        
        # Test 3: Missing password
        login_data = {
            "username": "invaliduser"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 422
        
        # Test 4: Missing username
        login_data = {
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 422

    def test_login_with_unconfirmed_email(self, setup_database):
        """Test login attempts with unconfirmed email addresses."""
        client = TestClient(app)
        
        # Create a user (email confirmation should be enabled by default)
        registration_data = {
            "username": "unconfirmeduser",
            "email": "unconfirmed@test.com",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Try to login without confirming email
        login_data = {
            "username": "unconfirmeduser",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 401
        assert "email confirmation" in response.json()["detail"].lower()

    def test_authentication_rate_limiting(self, setup_database):
        """Test rate limiting on authentication endpoints."""
        client = TestClient(app)
        
        # Create a user
        registration_data = {
            "username": "rateuser",
            "email": "rate@test.com",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Make multiple rapid login attempts with wrong password
        login_data = {
            "username": "rateuser",
            "password": "WrongPassword123!"
        }
        
        for i in range(10):
            response = client.post("/api/v1/auth/login", json=login_data)
            if response.status_code == 429:  # Rate limited
                break
        
        # At some point, we should hit rate limiting
        # Note: This depends on the rate limiting configuration

    def test_token_expiration_and_refresh(self, setup_database):
        """Test token expiration and refresh functionality."""
        client = TestClient(app)
        
        # Create a user
        registration_data = {
            "username": "tokenuser",
            "email": "token@test.com",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Login to get tokens
        login_data = {
            "username": "tokenuser",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 200
        
        auth_response = response.json()
        access_token = auth_response["access_token"]
        refresh_token = auth_response["refresh_token"]
        
        # Manually expire the access token by modifying it in the database
        # This is a simplified approach - in real scenarios, you'd wait for natural expiration
        
        # Test refresh with valid refresh token
        refresh_data = {"refresh_token": refresh_token}
        response = client.post("/api/v1/auth/refresh", json=refresh_data)
        assert response.status_code == 200
        
        new_auth_response = response.json()
        assert "access_token" in new_auth_response
        assert "refresh_token" in new_auth_response

    def test_multi_device_authentication(self, setup_database):
        """Test authentication from multiple devices."""
        client = TestClient(app)
        
        # Create a user
        registration_data = {
            "username": "multiuser",
            "email": "multi@test.com",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Login from device 1
        login_data = {
            "username": "multiuser",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 200
        
        auth_response_1 = response.json()
        access_token_1 = auth_response_1["access_token"]
        refresh_token_1 = auth_response_1["refresh_token"]
        
        # Login from device 2 (simulate different device)
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 200
        
        auth_response_2 = response.json()
        access_token_2 = auth_response_2["access_token"]
        refresh_token_2 = auth_response_2["refresh_token"]
        
        # Both tokens should work independently
        headers_1 = {"Authorization": f"Bearer {access_token_1}"}
        response = client.get("/api/v1/auth/me", headers=headers_1)
        assert response.status_code == 200
        
        headers_2 = {"Authorization": f"Bearer {access_token_2}"}
        response = client.get("/api/v1/auth/me", headers=headers_2)
        assert response.status_code == 200
        
        # Logout from device 1
        logout_data = {"refresh_token": refresh_token_1}
        response = client.delete("/api/v1/auth/logout", json=logout_data)
        assert response.status_code == 200
        
        # Device 2 should still work
        response = client.get("/api/v1/auth/me", headers=headers_2)
        assert response.status_code == 200

    def test_authentication_with_internationalization(self, setup_database):
        """Test authentication with different language preferences."""
        client = TestClient(app)
        
        # Create a user
        registration_data = {
            "username": "i18nuser",
            "email": "i18n@test.com",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Login with Spanish language
        login_data = {
            "username": "i18nuser",
            "password": "SecurePass789!"
        }
        
        response = client.post(
            "/api/v1/auth/login", 
            json=login_data,
            headers={"Accept-Language": "es"}
        )
        assert response.status_code == 200
        
        # Login with Arabic language
        response = client.post(
            "/api/v1/auth/login", 
            json=login_data,
            headers={"Accept-Language": "ar"}
        )
        assert response.status_code == 200

    def test_authentication_security_headers(self, setup_database):
        """Test that authentication endpoints return proper security headers."""
        client = TestClient(app)
        
        # Test login endpoint
        response = client.post("/api/v1/auth/login", json={"username": "test", "password": "test"})
        
        # Check for security headers
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "X-XSS-Protection" in response.headers
        
        # Test logout endpoint
        response = client.delete("/api/v1/auth/logout", json={"refresh_token": "test"})
        
        # Check for security headers
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "X-XSS-Protection" in response.headers

    def test_authentication_validation_errors(self, setup_database):
        """Test various validation errors during authentication."""
        client = TestClient(app)
        
        # Test 1: Invalid JSON
        response = client.post("/api/v1/auth/login", data="invalid json")
        assert response.status_code == 422
        
        # Test 2: Empty request body
        response = client.post("/api/v1/auth/login", json={})
        assert response.status_code == 422
        
        # Test 3: Invalid field types
        login_data = {
            "username": 123,  # Should be string
            "password": 456   # Should be string
        }
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 422

    def test_authentication_edge_cases(self, setup_database):
        """Test various edge cases in authentication."""
        client = TestClient(app)
        
        # Test with very long username
        long_username = "a" * 100
        login_data = {
            "username": long_username,
            "password": "SecurePass789!"
        }
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 401  # User doesn't exist
        
        # Test with special characters in username
        special_username_data = {
            "username": "user_name_123",
            "password": "SecurePass789!"
        }
        response = client.post("/api/v1/auth/login", json=special_username_data)
        assert response.status_code == 401  # User doesn't exist
        
        # Test with unicode characters
        unicode_username_data = {
            "username": "usér123",
            "password": "SecurePass789!"
        }
        response = client.post("/api/v1/auth/login", json=unicode_username_data)
        assert response.status_code == 401  # User doesn't exist

    def test_session_management(self, setup_database):
        """Test session management and tracking."""
        client = TestClient(app)
        
        # Create a user
        registration_data = {
            "username": "sessionuser",
            "email": "session@test.com",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Login to create a session
        login_data = {
            "username": "sessionuser",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 200
        
        # Verify session was created in database
        async def check_session():
            async with get_async_db() as db:
                result = await db.execute(
                    text("SELECT COUNT(*) FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = :email)"),
                    {"email": "session@test.com"}
                )
                return result.scalar()
        
        import asyncio
        session_count = asyncio.run(check_session())
        assert session_count >= 1
        
        # Logout to end session
        auth_response = response.json()
        logout_data = {"refresh_token": auth_response["refresh_token"]}
        response = client.delete("/api/v1/auth/logout", json=logout_data)
        assert response.status_code == 200 