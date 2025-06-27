"""
Tests for the logout endpoint.

This module tests the logout functionality, including internationalization
support and concurrent token revocation operations.
"""

import pytest
from unittest.mock import AsyncMock, patch
from fastapi import HTTPException
from jose import jwt

from src.adapters.api.v1.auth.routes.logout import logout_user
from src.adapters.api.v1.auth.schemas import LogoutRequest
from src.core.exceptions import AuthenticationError
from src.domain.entities.user import User, Role
from src.domain.services.auth.token import TokenService
from src.core.config.settings import settings


@pytest.fixture
def mock_request():
    """Mock FastAPI request with language state."""
    request = AsyncMock()
    request.state.language = "es"  # Spanish for testing i18n
    return request


@pytest.fixture
def mock_user():
    """Mock authenticated user."""
    return User(
        id=1,
        username="testuser",
        email="test@example.com",
        role=Role.USER,
        is_active=True
    )


@pytest.fixture
def mock_token_service():
    """Mock token service with proper async methods."""
    service = AsyncMock(spec=TokenService)
    service.validate_token.return_value = {"jti": "test-jti-123", "sub": "1"}
    service.revoke_access_token = AsyncMock()
    service.revoke_refresh_token = AsyncMock()
    return service


@pytest.fixture
def valid_refresh_token(mock_user):
    """Create a valid refresh token for testing."""
    payload = {
        "sub": str(mock_user.id),
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "exp": 9999999999,  # Far future expiration
        "iat": 1000000000,
        "jti": "refresh-jti-456"
    }
    return jwt.encode(payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256")


class TestLogoutEndpoint:
    """Test cases for the logout endpoint."""

    @pytest.mark.asyncio
    async def test_logout_success_with_i18n(
        self, 
        mock_request, 
        mock_user, 
        mock_token_service, 
        valid_refresh_token
    ):
        """Test successful logout with internationalization support."""
        # Arrange
        access_token = "valid-access-token"
        logout_payload = LogoutRequest(refresh_token=valid_refresh_token)
        
        # Act
        result = await logout_user(
            request=mock_request,
            payload=logout_payload,
            token=access_token,
            current_user=mock_user,
            token_service=mock_token_service
        )
        
        # Assert
        assert result.message == "Logged out successfully"
        
        # Verify token service calls with proper parameters
        mock_token_service.validate_token.assert_called_once_with(access_token, "es")
        mock_token_service.revoke_access_token.assert_called_once_with("test-jti-123")
        mock_token_service.revoke_refresh_token.assert_called_once_with(valid_refresh_token, "es")

    @pytest.mark.asyncio
    async def test_logout_concurrent_operations(
        self, 
        mock_request, 
        mock_user, 
        mock_token_service, 
        valid_refresh_token
    ):
        """Test that token revocation operations are executed concurrently."""
        # Arrange
        access_token = "valid-access-token"
        logout_payload = LogoutRequest(refresh_token=valid_refresh_token)
        
        # Track call order
        call_order = []
        
        orig_revoke_access_token = mock_token_service.revoke_access_token
        orig_revoke_refresh_token = mock_token_service.revoke_refresh_token
        
        async def track_revoke_access_token(jti):
            call_order.append("access")
            return await orig_revoke_access_token(jti)
        
        async def track_revoke_refresh_token(token, language):
            call_order.append("refresh")
            return await orig_revoke_refresh_token(token, language)
        
        mock_token_service.revoke_access_token = track_revoke_access_token
        mock_token_service.revoke_refresh_token = track_revoke_refresh_token
        
        # Act
        await logout_user(
            request=mock_request,
            payload=logout_payload,
            token=access_token,
            current_user=mock_user,
            token_service=mock_token_service
        )
        
        # Assert - both operations should be called (order may vary due to concurrency)
        assert len(call_order) == 2
        assert "access" in call_order
        assert "refresh" in call_order

    @pytest.mark.asyncio
    async def test_logout_refresh_token_ownership_validation(
        self, 
        mock_request, 
        mock_user, 
        mock_token_service
    ):
        """Test that refresh token ownership is properly validated."""
        # Arrange - create refresh token for different user
        different_user_payload = {
            "sub": "999",  # Different user ID
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "exp": 9999999999,
            "iat": 1000000000,
            "jti": "refresh-jti-456"
        }
        different_user_token = jwt.encode(
            different_user_payload, 
            settings.JWT_PRIVATE_KEY.get_secret_value(), 
            algorithm="RS256"
        )
        
        logout_payload = LogoutRequest(refresh_token=different_user_token)
        access_token = "valid-access-token"
        
        # Act & Assert
        with pytest.raises(AuthenticationError):
            await logout_user(
                request=mock_request,
                payload=logout_payload,
                token=access_token,
                current_user=mock_user,
                token_service=mock_token_service
            )

    @pytest.mark.asyncio
    async def test_logout_invalid_refresh_token(
        self, 
        mock_request, 
        mock_user, 
        mock_token_service
    ):
        """Test logout with invalid refresh token."""
        # Arrange
        invalid_refresh_token = "invalid.token.here"
        logout_payload = LogoutRequest(refresh_token=invalid_refresh_token)
        access_token = "valid-access-token"
        
        # Act & Assert
        with pytest.raises(AuthenticationError):
            await logout_user(
                request=mock_request,
                payload=logout_payload,
                token=access_token,
                current_user=mock_user,
                token_service=mock_token_service
            )

    @pytest.mark.asyncio
    async def test_logout_fallback_language(
        self, 
        mock_user, 
        mock_token_service, 
        valid_refresh_token
    ):
        """Test logout with fallback language when language is not set."""
        # Arrange - request without language state
        request = AsyncMock()
        request.state = None  # No language state
        
        logout_payload = LogoutRequest(refresh_token=valid_refresh_token)
        access_token = "valid-access-token"
        
        # Act
        result = await logout_user(
            request=request,
            payload=logout_payload,
            token=access_token,
            current_user=mock_user,
            token_service=mock_token_service
        )
        
        # Assert
        assert result.message == "Logged out successfully"
        
        # Verify fallback to 'en' language
        mock_token_service.validate_token.assert_called_once_with(access_token, "en")
        mock_token_service.revoke_refresh_token.assert_called_once_with(valid_refresh_token, "en")

    @pytest.mark.asyncio
    async def test_logout_token_service_error_handling(
        self, 
        mock_request, 
        mock_user, 
        mock_token_service, 
        valid_refresh_token
    ):
        """Test error handling when token service operations fail."""
        # Arrange
        mock_token_service.revoke_refresh_token.side_effect = AuthenticationError("Token service error")
        logout_payload = LogoutRequest(refresh_token=valid_refresh_token)
        access_token = "valid-access-token"
        
        # Act & Assert
        with pytest.raises(AuthenticationError):
            await logout_user(
                request=mock_request,
                payload=logout_payload,
                token=access_token,
                current_user=mock_user,
                token_service=mock_token_service
            ) 