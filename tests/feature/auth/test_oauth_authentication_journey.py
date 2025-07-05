"""
Comprehensive feature tests for OAuth authentication journey.

This test suite mirrors real-world OAuth scenarios including:
- Google OAuth authentication
- Microsoft OAuth authentication  
- Facebook OAuth authentication
- OAuth token validation and user creation
- OAuth profile linking and management
- Error handling and edge cases

These tests use real services and database interactions, similar to RSpec Rails integration tests.
"""

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import text
from unittest.mock import patch, MagicMock

from src.main import app
from src.infrastructure.database.async_db import get_async_db
from src.infrastructure.redis import get_redis
from src.core.config.settings import settings


class TestOAuthAuthenticationJourney:
    """End-to-end OAuth authentication journey tests."""

    @pytest_asyncio.fixture(autouse=True)
    async def setup_database(self):
        """Setup and cleanup database for each test."""
        async with get_async_db() as db:
            # Clean up any existing test data
            await db.execute(text("DELETE FROM users WHERE email LIKE '%@test.com'"))
            await db.execute(text("DELETE FROM oauth_profiles WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@test.com')"))
            await db.execute(text("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@test.com')"))
            await db.commit()
            yield db
            # Cleanup after test
            await db.execute(text("DELETE FROM users WHERE email LIKE '%@test.com'"))
            await db.execute(text("DELETE FROM oauth_profiles WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@test.com')"))
            await db.execute(text("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@test.com')"))
            await db.commit()

    @patch('src.infrastructure.services.authentication.oauth.requests.get')
    def test_google_oauth_authentication_journey(self, mock_get, setup_database):
        """Test complete Google OAuth authentication journey."""
        client = TestClient(app)
        
        # Mock Google OAuth user info response
        mock_google_user_info = {
            "id": "google_user_123",
            "email": "google@test.com",
            "name": "Google Test User",
            "given_name": "Google",
            "family_name": "Test User",
            "picture": "https://example.com/avatar.jpg",
            "verified_email": True
        }
        
        mock_get.return_value.json.return_value = mock_google_user_info
        mock_get.return_value.status_code = 200
        
        # Step 1: Authenticate with Google OAuth
        oauth_data = {
            "provider": "google",
            "token": {
                "access_token": "google_access_token_123",
                "expires_at": 1640995200
            }
        }
        
        response = client.post("/api/v1/auth/oauth", json=oauth_data)
        assert response.status_code == 200
        
        auth_response = response.json()
        assert "access_token" in auth_response
        assert "refresh_token" in auth_response
        assert "user" in auth_response
        
        user_data = auth_response["user"]
        assert user_data["email"] == "google@test.com"
        assert user_data["username"] is not None
        
        # Step 2: Verify user was created in database
        async def verify_user_creation():
            async with get_async_db() as db:
                result = await db.execute(
                    text("SELECT id, email, username FROM users WHERE email = :email"),
                    {"email": "google@test.com"}
                )
                return result.fetchone()
        
        import asyncio
        user_record = asyncio.run(verify_user_creation())
        assert user_record is not None
        assert user_record[1] == "google@test.com"
        
        # Step 3: Verify OAuth profile was created
        async def verify_oauth_profile():
            async with get_async_db() as db:
                result = await db.execute(
                    text("SELECT provider, provider_user_id FROM oauth_profiles WHERE user_id = :user_id"),
                    {"user_id": user_record[0]}
                )
                return result.fetchone()
        
        oauth_profile = asyncio.run(verify_oauth_profile())
        assert oauth_profile is not None
        assert oauth_profile[0] == "google"
        assert oauth_profile[1] == "google_user_123"
        
        # Step 4: Use the access token to access protected endpoints
        access_token = auth_response["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}
        response = client.get("/api/v1/auth/me", headers=headers)
        assert response.status_code == 200

    @patch('src.infrastructure.services.authentication.oauth.requests.get')
    def test_microsoft_oauth_authentication_journey(self, mock_get, setup_database):
        """Test complete Microsoft OAuth authentication journey."""
        client = TestClient(app)
        
        # Mock Microsoft OAuth user info response
        mock_microsoft_user_info = {
            "id": "microsoft_user_456",
            "mail": "microsoft@test.com",
            "displayName": "Microsoft Test User",
            "givenName": "Microsoft",
            "surname": "Test User",
            "userPrincipalName": "microsoft@test.com"
        }
        
        mock_get.return_value.json.return_value = mock_microsoft_user_info
        mock_get.return_value.status_code = 200
        
        # Step 1: Authenticate with Microsoft OAuth
        oauth_data = {
            "provider": "microsoft",
            "token": {
                "access_token": "microsoft_access_token_456",
                "expires_at": 1640995200
            }
        }
        
        response = client.post("/api/v1/auth/oauth", json=oauth_data)
        assert response.status_code == 200
        
        auth_response = response.json()
        assert "access_token" in auth_response
        assert "refresh_token" in auth_response
        assert "user" in auth_response
        
        user_data = auth_response["user"]
        assert user_data["email"] == "microsoft@test.com"
        assert user_data["username"] is not None
        
        # Step 2: Verify user and OAuth profile creation
        async def verify_microsoft_user():
            async with get_async_db() as db:
                result = await db.execute(
                    text("""
                        SELECT u.id, u.email, u.username, op.provider, op.provider_user_id 
                        FROM users u 
                        JOIN oauth_profiles op ON u.id = op.user_id 
                        WHERE u.email = :email
                    """),
                    {"email": "microsoft@test.com"}
                )
                return result.fetchone()
        
        import asyncio
        user_record = asyncio.run(verify_microsoft_user())
        assert user_record is not None
        assert user_record[1] == "microsoft@test.com"
        assert user_record[3] == "microsoft"
        assert user_record[4] == "microsoft_user_456"

    @patch('src.infrastructure.services.authentication.oauth.requests.get')
    def test_facebook_oauth_authentication_journey(self, mock_get, setup_database):
        """Test complete Facebook OAuth authentication journey."""
        client = TestClient(app)
        
        # Mock Facebook OAuth user info response
        mock_facebook_user_info = {
            "id": "facebook_user_789",
            "email": "facebook@test.com",
            "name": "Facebook Test User",
            "first_name": "Facebook",
            "last_name": "Test User"
        }
        
        mock_get.return_value.json.return_value = mock_facebook_user_info
        mock_get.return_value.status_code = 200
        
        # Step 1: Authenticate with Facebook OAuth
        oauth_data = {
            "provider": "facebook",
            "token": {
                "access_token": "facebook_access_token_789",
                "expires_at": 1640995200
            }
        }
        
        response = client.post("/api/v1/auth/oauth", json=oauth_data)
        assert response.status_code == 200
        
        auth_response = response.json()
        assert "access_token" in auth_response
        assert "refresh_token" in auth_response
        assert "user" in auth_response
        
        user_data = auth_response["user"]
        assert user_data["email"] == "facebook@test.com"
        assert user_data["username"] is not None
        
        # Step 2: Verify user and OAuth profile creation
        async def verify_facebook_user():
            async with get_async_db() as db:
                result = await db.execute(
                    text("""
                        SELECT u.id, u.email, u.username, op.provider, op.provider_user_id 
                        FROM users u 
                        JOIN oauth_profiles op ON u.id = op.user_id 
                        WHERE u.email = :email
                    """),
                    {"email": "facebook@test.com"}
                )
                return result.fetchone()
        
        import asyncio
        user_record = asyncio.run(verify_facebook_user())
        assert user_record is not None
        assert user_record[1] == "facebook@test.com"
        assert user_record[3] == "facebook"
        assert user_record[4] == "facebook_user_789"

    @patch('src.infrastructure.services.authentication.oauth.requests.get')
    def test_oauth_existing_user_linking(self, mock_get, setup_database):
        """Test OAuth authentication for existing users."""
        client = TestClient(app)
        
        # Step 1: Create a user with traditional registration
        registration_data = {
            "username": "existinguser",
            "email": "existing@test.com",
            "password": "SecurePass789!"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        assert response.status_code == 201
        
        # Step 2: Mock OAuth response for the same email
        mock_oauth_user_info = {
            "id": "oauth_user_123",
            "email": "existing@test.com",
            "name": "OAuth Test User",
            "given_name": "OAuth",
            "family_name": "Test User"
        }
        
        mock_get.return_value.json.return_value = mock_oauth_user_info
        mock_get.return_value.status_code = 200
        
        # Step 3: Authenticate with OAuth using same email
        oauth_data = {
            "provider": "google",
            "token": {
                "access_token": "oauth_access_token_123",
                "expires_at": 1640995200
            }
        }
        
        response = client.post("/api/v1/auth/oauth", json=oauth_data)
        assert response.status_code == 200
        
        auth_response = response.json()
        assert "access_token" in auth_response
        assert "user" in auth_response
        
        user_data = auth_response["user"]
        assert user_data["email"] == "existing@test.com"
        assert user_data["username"] == "existinguser"  # Should keep existing username
        
        # Step 4: Verify OAuth profile was linked to existing user
        async def verify_oauth_linking():
            async with get_async_db() as db:
                result = await db.execute(
                    text("""
                        SELECT u.id, u.email, u.username, op.provider, op.provider_user_id 
                        FROM users u 
                        JOIN oauth_profiles op ON u.id = op.user_id 
                        WHERE u.email = :email AND op.provider = :provider
                    """),
                    {"email": "existing@test.com", "provider": "google"}
                )
                return result.fetchone()
        
        import asyncio
        user_record = asyncio.run(verify_oauth_linking())
        assert user_record is not None
        assert user_record[1] == "existing@test.com"
        assert user_record[2] == "existinguser"
        assert user_record[3] == "google"

    @patch('src.infrastructure.services.authentication.oauth.requests.get')
    def test_oauth_invalid_token_handling(self, mock_get, setup_database):
        """Test OAuth authentication with invalid tokens."""
        client = TestClient(app)
        
        # Mock invalid token response
        mock_get.return_value.status_code = 401
        mock_get.return_value.json.return_value = {"error": "invalid_token"}
        
        oauth_data = {
            "provider": "google",
            "token": {
                "access_token": "invalid_token_123",
                "expires_at": 1640995200
            }
        }
        
        response = client.post("/api/v1/auth/oauth", json=oauth_data)
        assert response.status_code == 401
        assert "invalid" in response.json()["detail"].lower()

    def test_oauth_unsupported_provider(self, setup_database):
        """Test OAuth authentication with unsupported provider."""
        client = TestClient(app)
        
        oauth_data = {
            "provider": "unsupported_provider",
            "token": {
                "access_token": "test_token_123",
                "expires_at": 1640995200
            }
        }
        
        response = client.post("/api/v1/auth/oauth", json=oauth_data)
        assert response.status_code == 422  # Validation error for unsupported provider

    def test_oauth_missing_token_data(self, setup_database):
        """Test OAuth authentication with missing token data."""
        client = TestClient(app)
        
        # Test with missing access_token
        oauth_data = {
            "provider": "google",
            "token": {
                "expires_at": 1640995200
            }
        }
        
        response = client.post("/api/v1/auth/oauth", json=oauth_data)
        assert response.status_code == 422
        
        # Test with missing token object
        oauth_data = {
            "provider": "google"
        }
        
        response = client.post("/api/v1/auth/oauth", json=oauth_data)
        assert response.status_code == 422

    @patch('src.infrastructure.services.authentication.oauth.requests.get')
    def test_oauth_network_error_handling(self, mock_get, setup_database):
        """Test OAuth authentication with network errors."""
        client = TestClient(app)
        
        # Mock network error
        mock_get.side_effect = Exception("Network error")
        
        oauth_data = {
            "provider": "google",
            "token": {
                "access_token": "test_token_123",
                "expires_at": 1640995200
            }
        }
        
        response = client.post("/api/v1/auth/oauth", json=oauth_data)
        assert response.status_code == 500  # Internal server error

    @patch('src.infrastructure.services.authentication.oauth.requests.get')
    def test_oauth_multiple_providers_same_user(self, mock_get, setup_database):
        """Test linking multiple OAuth providers to the same user."""
        client = TestClient(app)
        
        # Mock Google OAuth response
        mock_google_user_info = {
            "id": "google_user_123",
            "email": "multi@test.com",
            "name": "Multi Provider User",
            "given_name": "Multi",
            "family_name": "Provider User"
        }
        
        mock_get.return_value.json.return_value = mock_google_user_info
        mock_get.return_value.status_code = 200
        
        # Step 1: Authenticate with Google
        oauth_data = {
            "provider": "google",
            "token": {
                "access_token": "google_token_123",
                "expires_at": 1640995200
            }
        }
        
        response = client.post("/api/v1/auth/oauth", json=oauth_data)
        assert response.status_code == 200
        
        # Step 2: Mock Microsoft OAuth response for same email
        mock_microsoft_user_info = {
            "id": "microsoft_user_456",
            "mail": "multi@test.com",
            "displayName": "Multi Provider User",
            "givenName": "Multi",
            "surname": "Provider User"
        }
        
        mock_get.return_value.json.return_value = mock_microsoft_user_info
        
        # Step 3: Authenticate with Microsoft (should link to existing user)
        oauth_data = {
            "provider": "microsoft",
            "token": {
                "access_token": "microsoft_token_456",
                "expires_at": 1640995200
            }
        }
        
        response = client.post("/api/v1/auth/oauth", json=oauth_data)
        assert response.status_code == 200
        
        # Step 4: Verify both OAuth profiles are linked
        async def verify_multiple_providers():
            async with get_async_db() as db:
                result = await db.execute(
                    text("""
                        SELECT op.provider, op.provider_user_id 
                        FROM oauth_profiles op 
                        JOIN users u ON op.user_id = u.id 
                        WHERE u.email = :email
                        ORDER BY op.provider
                    """),
                    {"email": "multi@test.com"}
                )
                return result.fetchall()
        
        import asyncio
        oauth_profiles = asyncio.run(verify_multiple_providers())
        assert len(oauth_profiles) == 2
        
        providers = [profile[0] for profile in oauth_profiles]
        assert "google" in providers
        assert "microsoft" in providers

    def test_oauth_validation_errors(self, setup_database):
        """Test various validation errors in OAuth authentication."""
        client = TestClient(app)
        
        # Test 1: Invalid provider
        oauth_data = {
            "provider": "invalid_provider",
            "token": {
                "access_token": "test_token",
                "expires_at": 1640995200
            }
        }
        response = client.post("/api/v1/auth/oauth", json=oauth_data)
        assert response.status_code == 422
        
        # Test 2: Missing provider
        oauth_data = {
            "token": {
                "access_token": "test_token",
                "expires_at": 1640995200
            }
        }
        response = client.post("/api/v1/auth/oauth", json=oauth_data)
        assert response.status_code == 422
        
        # Test 3: Invalid token structure
        oauth_data = {
            "provider": "google",
            "token": "invalid_token_string"
        }
        response = client.post("/api/v1/auth/oauth", json=oauth_data)
        assert response.status_code == 422

    def test_oauth_security_headers(self, setup_database):
        """Test that OAuth endpoints return proper security headers."""
        client = TestClient(app)
        
        response = client.post("/api/v1/auth/oauth", json={"provider": "google", "token": {}})
        
        # Check for security headers
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "X-XSS-Protection" in response.headers 