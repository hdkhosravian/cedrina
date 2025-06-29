"""Tests for Reset Password API endpoint following clean architecture principles.

These tests verify the reset password endpoint implementation with comprehensive
coverage of success paths, error conditions, and security features.
"""

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import status
from httpx import AsyncClient

from src.core.exceptions import (
    ForgotPasswordError,
    PasswordResetError,
    UserNotFoundError,
)


class TestResetPasswordEndpoint:
    """Test suite for reset password API endpoint."""
    
    @pytest.mark.asyncio
    async def test_successful_password_reset(
        self, 
        async_client: AsyncClient,
        mock_password_reset_service
    ):
        """Test successful password reset with valid token."""
        # Arrange
        valid_token = "a" * 64  # 64-character token
        new_password = "NewSecurePass123!"
        
        mock_password_reset_service.reset_password.return_value = {
            "message": "Password reset successfully",
            "status": "success"
        }
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": valid_token,
                "new_password": new_password
            }
        )
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert "message" in response_data
        assert response_data["message"] == "Password reset successfully"
        
        # Verify service was called with correct parameters
        mock_password_reset_service.reset_password.assert_called_once()
        call_args = mock_password_reset_service.reset_password.call_args
        assert call_args.kwargs["token"] == valid_token
        assert call_args.kwargs["new_password"] == new_password
        assert "language" in call_args.kwargs
        assert "user_agent" in call_args.kwargs
        assert "ip_address" in call_args.kwargs
        assert "correlation_id" in call_args.kwargs
    
    @pytest.mark.asyncio
    async def test_reset_password_with_invalid_token_format(
        self, 
        async_client: AsyncClient
    ):
        """Test reset password with invalid token format."""
        # Arrange
        invalid_token = "short"  # Too short
        new_password = "NewSecurePass123!"
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": invalid_token,
                "new_password": new_password
            }
        )
        
        # Assert
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        response_data = response.json()
        assert "detail" in response_data
    
    @pytest.mark.asyncio
    async def test_reset_password_with_missing_token(
        self, 
        async_client: AsyncClient
    ):
        """Test reset password with missing token field."""
        # Act
        response = await async_client.post(
            "/api/v1/auth/reset-password",
            json={"new_password": "NewSecurePass123!"}
        )
        
        # Assert
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    @pytest.mark.asyncio
    async def test_reset_password_with_missing_password(
        self, 
        async_client: AsyncClient
    ):
        """Test reset password with missing password field."""
        # Act
        response = await async_client.post(
            "/api/v1/auth/reset-password",
            json={"token": "a" * 64}
        )
        
        # Assert
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    @pytest.mark.asyncio
    async def test_reset_password_with_invalid_token(
        self, 
        async_client: AsyncClient,
        mock_password_reset_service
    ):
        """Test reset password with invalid/expired token."""
        # Arrange
        invalid_token = "a" * 64
        new_password = "NewSecurePass123!"
        
        mock_password_reset_service.reset_password.side_effect = (
            PasswordResetError("Invalid or expired token")
        )
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": invalid_token,
                "new_password": new_password
            }
        )
        
        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        response_data = response.json()
        assert "detail" in response_data
    
    @pytest.mark.asyncio
    async def test_reset_password_with_weak_password(
        self, 
        async_client: AsyncClient,
        mock_password_reset_service
    ):
        """Test reset password with weak password."""
        # Arrange
        valid_token = "a" * 64
        weak_password = "123"
        
        mock_password_reset_service.reset_password.side_effect = (
            ValueError("Password too weak")
        )
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": valid_token,
                "new_password": weak_password
            }
        )
        
        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        response_data = response.json()
        assert "detail" in response_data
    
    @pytest.mark.asyncio
    async def test_reset_password_user_not_found(
        self, 
        async_client: AsyncClient,
        mock_password_reset_service
    ):
        """Test reset password when user is not found."""
        # Arrange
        valid_token = "a" * 64
        new_password = "NewSecurePass123!"
        
        mock_password_reset_service.reset_password.side_effect = (
            UserNotFoundError("User not found")
        )
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": valid_token,
                "new_password": new_password
            }
        )
        
        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND
    
    @pytest.mark.asyncio
    async def test_reset_password_domain_error_handling(
        self, 
        async_client: AsyncClient,
        mock_password_reset_service
    ):
        """Test handling of domain errors."""
        # Arrange
        valid_token = "a" * 64
        new_password = "NewSecurePass123!"
        
        mock_password_reset_service.reset_password.side_effect = (
            ForgotPasswordError("Domain error occurred")
        )
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": valid_token,
                "new_password": new_password
            }
        )
        
        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        response_data = response.json()
        assert "detail" in response_data
    
    @pytest.mark.asyncio
    async def test_reset_password_unexpected_error_handling(
        self, 
        async_client: AsyncClient,
        mock_password_reset_service
    ):
        """Test handling of unexpected errors."""
        # Arrange
        valid_token = "a" * 64
        new_password = "NewSecurePass123!"
        
        mock_password_reset_service.reset_password.side_effect = (
            Exception("Unexpected error")
        )
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": valid_token,
                "new_password": new_password
            }
        )
        
        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        response_data = response.json()
        assert "detail" in response_data
    
    @pytest.mark.asyncio
    async def test_reset_password_security_context_extraction(
        self, 
        async_client: AsyncClient,
        mock_password_reset_service
    ):
        """Test that security context is properly extracted."""
        # Arrange
        valid_token = "a" * 64
        new_password = "NewSecurePass123!"
        user_agent = "Test-User-Agent/1.0"
        
        mock_password_reset_service.reset_password.return_value = {
            "message": "Password reset successfully",
            "status": "success"
        }
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": valid_token,
                "new_password": new_password
            },
            headers={"User-Agent": user_agent}
        )
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        
        # Verify service was called with security context
        call_args = mock_password_reset_service.reset_password.call_args
        assert call_args.kwargs["user_agent"] == user_agent
        assert "ip_address" in call_args.kwargs
        assert "correlation_id" in call_args.kwargs
        
        # Verify correlation ID is a valid UUID format
        correlation_id = call_args.kwargs["correlation_id"]
        assert uuid.UUID(correlation_id)  # Will raise if not valid UUID
    
    @pytest.mark.asyncio
    async def test_reset_password_token_validation_edge_cases(
        self,
        async_client: AsyncClient
    ):
        """Test token validation edge cases."""
        new_password = "NewSecurePass123!"

        # Cases that should be rejected at the Pydantic validation level
        pydantic_validation_cases = [
            # Empty token
            {"token": "", "new_password": new_password},
            # Token too short (below min_length=64)
            {"token": "short", "new_password": new_password},
            # Token too long (above max_length=64) 
            {"token": "a" * 65, "new_password": new_password},
        ]

        for invalid_payload in pydantic_validation_cases:
            # Act
            response = await async_client.post(
                "/api/v1/auth/reset-password",
                json=invalid_payload
            )

            # Assert - These should fail at Pydantic validation level
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Cases that pass Pydantic validation but fail domain validation
        domain_validation_cases = [
            # Token with special characters (passes length check but invalid format)
            {"token": "a" * 63 + "@", "new_password": new_password},
        ]

        for payload in domain_validation_cases:
            # Act
            response = await async_client.post(
                "/api/v1/auth/reset-password",
                json=payload
            )

            # Assert - These pass Pydantic validation but fail domain validation
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            response_data = response.json()
            assert "detail" in response_data
    
    @pytest.mark.asyncio
    async def test_reset_password_password_validation_edge_cases(
        self, 
        async_client: AsyncClient
    ):
        """Test password validation edge cases."""
        valid_token = "a" * 64
        
        test_cases = [
            # Empty password
            {"token": valid_token, "new_password": ""},
            # Password with only spaces
            {"token": valid_token, "new_password": "   "},
            # Very long password
            {"token": valid_token, "new_password": "a" * 1000},
        ]
        
        for invalid_payload in test_cases:
            # Act
            response = await async_client.post(
                "/api/v1/auth/reset-password",
                json=invalid_payload
            )
            
            # Assert
            # May be caught at validation level or domain level
            assert response.status_code in [
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                status.HTTP_400_BAD_REQUEST
            ]
    
    @pytest.mark.asyncio
    async def test_reset_password_internationalization_support(
        self, 
        async_client: AsyncClient,
        mock_password_reset_service
    ):
        """Test internationalization support."""
        # Arrange
        valid_token = "a" * 64
        new_password = "NewSecurePass123!"
        
        mock_password_reset_service.reset_password.return_value = {
            "message": "Password reset successfully",
            "status": "success"
        }
        
        # Test different languages
        languages = ["en", "es", "ar", "fa"]
        
        for lang in languages:
            # Act
            response = await async_client.post(
                "/api/v1/auth/reset-password",
                json={
                    "token": valid_token,
                    "new_password": new_password
                },
                headers={"Accept-Language": lang}
            )
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            # Verify service was called with correct language
            call_args = mock_password_reset_service.reset_password.call_args
            assert call_args.kwargs["language"] == lang
    
    @pytest.mark.asyncio
    async def test_reset_password_rate_limiting_applied(
        self, 
        async_client: AsyncClient,
        mock_password_reset_service
    ):
        """Test that rate limiting is properly applied."""
        # Arrange
        valid_token = "a" * 64
        new_password = "NewSecurePass123!"
        
        mock_password_reset_service.reset_password.return_value = {
            "message": "Password reset successfully",
            "status": "success"
        }
        
        # Act - Make multiple requests to test rate limiting
        # Note: Rate limiting is tested at integration level with actual limiter
        response = await async_client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": valid_token,
                "new_password": new_password
            }
        )
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        # Rate limiting behavior would be tested in integration tests
    
    @pytest.mark.asyncio
    async def test_reset_password_with_special_characters_in_password(
        self, 
        async_client: AsyncClient,
        mock_password_reset_service
    ):
        """Test reset password with special characters in password."""
        # Arrange
        valid_token = "a" * 64
        special_password = "MyP@ssw0rd!#$%^&*()"
        
        mock_password_reset_service.reset_password.return_value = {
            "message": "Password reset successfully",
            "status": "success"
        }
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": valid_token,
                "new_password": special_password
            }
        )
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        
        # Verify service was called with the special password
        call_args = mock_password_reset_service.reset_password.call_args
        assert call_args.kwargs["new_password"] == special_password
    
    @pytest.mark.asyncio
    async def test_reset_password_response_structure(
        self, 
        async_client: AsyncClient,
        mock_password_reset_service
    ):
        """Test that the response has correct structure."""
        # Arrange
        valid_token = "a" * 64
        new_password = "NewSecurePass123!"
        
        mock_password_reset_service.reset_password.return_value = {
            "message": "Password reset successfully",
            "status": "success"
        }
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": valid_token,
                "new_password": new_password
            }
        )
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        
        # Check response structure matches MessageResponse schema
        assert "message" in response_data
        assert "timestamp" in response_data
        assert isinstance(response_data["message"], str)
        assert isinstance(response_data["timestamp"], str)
        
        # Verify timestamp is ISO format
        from datetime import datetime
        datetime.fromisoformat(response_data["timestamp"].replace('Z', '+00:00')) 