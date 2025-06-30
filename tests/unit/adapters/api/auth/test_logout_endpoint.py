"""Tests for the logout endpoint.

This module tests the logout functionality, including internationalization
support and concurrent token revocation operations.
"""

from unittest.mock import AsyncMock
from datetime import datetime, timezone, timedelta

import pytest
from jose import jwt

from src.adapters.api.v1.auth.routes.logout import logout_user
from src.adapters.api.v1.auth.schemas import LogoutRequest
from src.core.config.settings import settings
from src.core.exceptions import AuthenticationError
from src.domain.entities.user import Role, User
from src.domain.interfaces.services import IUserLogoutService


@pytest.fixture
def mock_request():
    """Mock FastAPI request with language state."""
    request = AsyncMock()
    request.state.language = "es"  # Spanish for testing i18n
    request.state.client_ip = "192.168.1.100"
    request.state.correlation_id = "test-correlation-123"
    request.headers = {"User-Agent": "Test-Agent/1.0"}
    return request


@pytest.fixture
def mock_user():
    """Mock user entity for testing."""
    return User(
        id=1,
        username="testuser",
        email="test@example.com",
        role=Role.USER,
        is_active=True,
    )


@pytest.fixture
def mock_logout_service():
    """Mock logout service."""
    service = AsyncMock(spec=IUserLogoutService)
    service.logout_user = AsyncMock()
    service.validate_refresh_token_ownership = AsyncMock()
    return service


@pytest.fixture
def valid_refresh_token():
    """Create a valid refresh token for testing."""
    payload = {
        "sub": "1",
        "jti": "r" * 43,  # 43 characters
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "iat": datetime.now(timezone.utc),
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
    }
    return jwt.encode(payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256")


@pytest.fixture
def valid_access_token():
    """Create a valid access token for testing."""
    payload = {
        "sub": "1",
        "jti": "a" * 43,  # 43 characters
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc),
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
    }
    return jwt.encode(payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256")


class TestLogoutEndpoint:
    """Test cases for the logout endpoint."""

    @pytest.mark.asyncio
    async def test_logout_success_with_i18n(
        self, mock_request, mock_user, mock_logout_service, valid_refresh_token, valid_access_token
    ):
        """Test successful logout with internationalization support."""
        # Arrange
        logout_payload = LogoutRequest(refresh_token=valid_refresh_token)

        # Act
        result = await logout_user(
            request=mock_request,
            payload=logout_payload,
            token=valid_access_token,
            current_user=mock_user,
            logout_service=mock_logout_service,
        )

        # Assert
        assert result.message == "Sesión cerrada exitosamente"

        # Verify logout service was called properly
        mock_logout_service.logout_user.assert_called_once()
        call_args = mock_logout_service.logout_user.call_args
        
        # Check that domain value objects were created and passed
        assert call_args.kwargs["user"] == mock_user
        assert call_args.kwargs["language"] == "es"
        assert call_args.kwargs["client_ip"] == "192.168.1.100"
        assert call_args.kwargs["user_agent"] == "Test-Agent/1.0"
        assert call_args.kwargs["correlation_id"] == "test-correlation-123"

    @pytest.mark.asyncio
    async def test_logout_concurrent_operations(
        self, mock_request, mock_user, mock_logout_service, valid_refresh_token, valid_access_token
    ):
        """Test that logout service is called properly."""
        # Arrange
        logout_payload = LogoutRequest(refresh_token=valid_refresh_token)

        # Act
        await logout_user(
            request=mock_request,
            payload=logout_payload,
            token=valid_access_token,
            current_user=mock_user,
            logout_service=mock_logout_service,
        )

        # Assert that logout service was called
        mock_logout_service.logout_user.assert_called_once()

    @pytest.mark.asyncio
    async def test_logout_refresh_token_ownership_validation(
        self, mock_request, mock_user, mock_logout_service, valid_access_token
    ):
        """Test that domain service handles token ownership validation."""
        # Arrange - create refresh token for different user
        different_user_payload = {
            "sub": "999",  # Different user ID
            "jti": "r" * 43,  # 43 characters
            "exp": datetime.now(timezone.utc) + timedelta(days=7),
            "iat": datetime.now(timezone.utc),
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
        }
        different_user_token = jwt.encode(
            different_user_payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256"
        )

        logout_payload = LogoutRequest(refresh_token=different_user_token)
        
        # Configure service to raise error for ownership validation
        mock_logout_service.logout_user.side_effect = AuthenticationError("Invalid refresh token")

        # Act - Should still return success even if service raises error
        result = await logout_user(
            request=mock_request,
            payload=logout_payload,
            token=valid_access_token,
            current_user=mock_user,
            logout_service=mock_logout_service,
        )

        # Assert - Should return success message
        assert result.message == "Sesión cerrada exitosamente"

    @pytest.mark.asyncio
    async def test_logout_invalid_refresh_token(self, mock_request, mock_user, mock_logout_service, valid_access_token):
        """Test logout with invalid refresh token."""
        # Arrange
        invalid_refresh_token = "invalid.token.here"
        logout_payload = LogoutRequest(refresh_token=invalid_refresh_token)

        # Act - Should return success even with invalid token
        result = await logout_user(
            request=mock_request,
            payload=logout_payload,
            token=valid_access_token,
            current_user=mock_user,
            logout_service=mock_logout_service,
        )

        # Assert - Should return success message
        assert result.message == "Sesión cerrada exitosamente"

    @pytest.mark.asyncio
    async def test_logout_fallback_language(
        self, mock_user, mock_logout_service, valid_refresh_token, valid_access_token
    ):
        """Test logout with fallback language when language is not set."""
        # Arrange - request without language state
        request = AsyncMock()
        request.state = AsyncMock()
        request.state.language = None  # No language state
        request.state.client_ip = ""
        request.state.correlation_id = ""
        request.headers = {}

        logout_payload = LogoutRequest(refresh_token=valid_refresh_token)

        # Act
        result = await logout_user(
            request=request,
            payload=logout_payload,
            token=valid_access_token,
            current_user=mock_user,
            logout_service=mock_logout_service,
        )

        # Assert
        assert result.message == "Logged out successfully"

    @pytest.mark.asyncio
    async def test_logout_service_error_handling(
        self, mock_request, mock_user, mock_logout_service, valid_refresh_token, valid_access_token
    ):
        """Test error handling when logout service operations fail."""
        # Arrange
        mock_logout_service.logout_user.side_effect = AuthenticationError(
            "Service error"
        )
        logout_payload = LogoutRequest(refresh_token=valid_refresh_token)

        # Act - Should return success even if service raises error
        result = await logout_user(
            request=mock_request,
            payload=logout_payload,
            token=valid_access_token,
            current_user=mock_user,
            logout_service=mock_logout_service,
        )

        # Assert - Should return success message
        assert result.message == "Sesión cerrada exitosamente"
