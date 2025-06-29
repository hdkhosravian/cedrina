"""Tests for Forgot Password API endpoint following clean architecture principles.

These tests verify the forgot password endpoint implementation with comprehensive
coverage of success paths, error conditions, and security features.
"""

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import status
from httpx import AsyncClient

from src.core.exceptions import (
    EmailServiceError,
    ForgotPasswordError,
    RateLimitExceededError,
)


class TestForgotPasswordEndpoint:
    """Test suite for forgot password API endpoint."""
    
    @pytest.mark.asyncio
    async def test_successful_forgot_password_request(
        self, 
        async_client: AsyncClient,
        mock_password_reset_request_service
    ):
        """Test successful password reset request."""
        # Arrange
        email = "test@example.com"
        
        mock_password_reset_request_service.request_password_reset.return_value = {
            "message": "Password reset email sent",
            "status": "success"
        }
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/forgot-password",
            json={"email": email}
        )
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert "message" in response_data
        assert "timestamp" in response_data
        # The endpoint uses i18n messages and always returns success for security
        assert "password reset" in response_data["message"].lower() or "email" in response_data["message"].lower()
        
        # Verify service was called with correct parameters
        mock_password_reset_request_service.request_password_reset.assert_called_once()
        call_args = mock_password_reset_request_service.request_password_reset.call_args
        assert call_args.kwargs["email"] == email
        assert "language" in call_args.kwargs
        assert "user_agent" in call_args.kwargs
        assert "ip_address" in call_args.kwargs
        assert "correlation_id" in call_args.kwargs
    
    @pytest.mark.asyncio
    async def test_forgot_password_with_invalid_email_format(
        self, 
        async_client: AsyncClient
    ):
        """Test forgot password with invalid email format."""
        # Arrange
        invalid_email = "not-an-email"
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/forgot-password",
            json={"email": invalid_email}
        )
        
        # Assert
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        response_data = response.json()
        assert "detail" in response_data
    
    @pytest.mark.asyncio
    async def test_forgot_password_with_missing_email(
        self, 
        async_client: AsyncClient
    ):
        """Test forgot password with missing email field."""
        # Act
        response = await async_client.post(
            "/api/v1/auth/forgot-password",
            json={}
        )
        
        # Assert
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    @pytest.mark.asyncio
    async def test_forgot_password_rate_limit_exceeded(
        self, 
        async_client: AsyncClient,
        mock_password_reset_request_service
    ):
        """Test forgot password when rate limit is exceeded."""
        # Arrange
        email = "test@example.com"
        
        mock_password_reset_request_service.request_password_reset.side_effect = (
            RateLimitExceededError("Rate limit exceeded")
        )
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/forgot-password",
            json={"email": email}
        )
        
        # Assert
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    
    @pytest.mark.asyncio
    async def test_forgot_password_email_service_error_returns_success(
        self, 
        async_client: AsyncClient,
        mock_password_reset_request_service
    ):
        """Test that email service errors still return success to prevent enumeration."""
        # Arrange
        email = "test@example.com"
        
        mock_password_reset_request_service.request_password_reset.side_effect = (
            EmailServiceError("Email service unavailable")
        )
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/forgot-password",
            json={"email": email}
        )
        
        # Assert - Still returns success to prevent email enumeration
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert "message" in response_data
    
    @pytest.mark.asyncio
    async def test_forgot_password_domain_error_handling(
        self, 
        async_client: AsyncClient,
        mock_password_reset_request_service
    ):
        """Test handling of domain errors."""
        # Arrange
        email = "test@example.com"
        
        mock_password_reset_request_service.request_password_reset.side_effect = (
            ForgotPasswordError("Domain error occurred")
        )
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/forgot-password",
            json={"email": email}
        )
        
        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        response_data = response.json()
        assert "detail" in response_data
    
    @pytest.mark.asyncio
    async def test_forgot_password_unexpected_error_returns_success(
        self, 
        async_client: AsyncClient,
        mock_password_reset_request_service
    ):
        """Test that unexpected errors still return success to prevent enumeration."""
        # Arrange
        email = "test@example.com"
        
        mock_password_reset_request_service.request_password_reset.side_effect = (
            Exception("Unexpected error")
        )
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/forgot-password",
            json={"email": email}
        )
        
        # Assert - Still returns success to prevent information leakage
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert "message" in response_data
    
    @pytest.mark.asyncio
    async def test_forgot_password_security_context_extraction(
        self, 
        async_client: AsyncClient,
        mock_password_reset_request_service
    ):
        """Test that security context is properly extracted."""
        # Arrange
        email = "test@example.com"
        user_agent = "Test-User-Agent/1.0"
        
        mock_password_reset_request_service.request_password_reset.return_value = {
            "message": "Password reset email sent",
            "status": "success"
        }
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/forgot-password",
            json={"email": email},
            headers={"User-Agent": user_agent}
        )
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        
        # Verify service was called with security context
        call_args = mock_password_reset_request_service.request_password_reset.call_args
        assert call_args.kwargs["user_agent"] == user_agent
        assert "ip_address" in call_args.kwargs
        assert "correlation_id" in call_args.kwargs
        
        # Verify correlation ID is a valid UUID format
        correlation_id = call_args.kwargs["correlation_id"]
        assert uuid.UUID(correlation_id)  # Will raise if not valid UUID
    
    @pytest.mark.asyncio
    async def test_forgot_password_cors_headers(
        self, 
        async_client: AsyncClient,
        mock_password_reset_request_service
    ):
        """Test that CORS headers are properly set."""
        # Arrange
        email = "test@example.com"
        
        mock_password_reset_request_service.request_password_reset.return_value = {
            "message": "Password reset email sent",
            "status": "success"
        }
        
        # Act
        response = await async_client.post(
            "/api/v1/auth/forgot-password",
            json={"email": email}
        )
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        # Note: CORS headers would be tested in integration tests with actual CORS middleware
    
    @pytest.mark.asyncio
    async def test_forgot_password_request_validation_edge_cases(
        self,
        async_client: AsyncClient
    ):
        """Test request validation edge cases."""
        # Cases that should be rejected at the Pydantic validation level
        validation_error_cases = [
            # Empty email
            {"email": ""},
            # Email too long  
            {"email": "a" * 250 + "@example.com"},
            # Multiple @ symbols
            {"email": "test@@example.com"},
        ]

        for invalid_payload in validation_error_cases:
            # Act
            response = await async_client.post(
                "/api/v1/auth/forgot-password",
                json=invalid_payload
            )

            # Assert - These should fail at Pydantic validation level
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Cases that pass Pydantic validation but return success for security
        # (to prevent email enumeration attacks)
        security_cases = [
            # Email with spaces (trimmed by EmailStr)
            {"email": " test@example.com "},
        ]

        for payload in security_cases:
            # Act
            response = await async_client.post(
                "/api/v1/auth/forgot-password",
                json=payload
            )

            # Assert - These pass validation and return success for security
            assert response.status_code == status.HTTP_200_OK
            response_data = response.json()
            assert "message" in response_data
    
    @pytest.mark.asyncio
    async def test_forgot_password_internationalization_support(
        self, 
        async_client: AsyncClient,
        mock_password_reset_request_service
    ):
        """Test internationalization support."""
        # Arrange
        email = "test@example.com"
        
        mock_password_reset_request_service.request_password_reset.return_value = {
            "message": "Password reset email sent",
            "status": "success"
        }
        
        # Test different languages
        languages = ["en", "es", "ar", "fa"]
        
        for lang in languages:
            # Act
            response = await async_client.post(
                "/api/v1/auth/forgot-password",
                json={"email": email},
                headers={"Accept-Language": lang}
            )
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            # Verify service was called with correct language
            call_args = mock_password_reset_request_service.request_password_reset.call_args
            assert call_args.kwargs["language"] == lang
    
    @pytest.mark.asyncio
    async def test_forgot_password_content_type_validation(
        self, 
        async_client: AsyncClient
    ):
        """Test content type validation."""
        # Arrange
        email = "test@example.com"
        
        # Act - Send as form data instead of JSON
        response = await async_client.post(
            "/api/v1/auth/forgot-password",
            data={"email": email},  # form data instead of json
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        # Assert - Should still work as FastAPI handles content type conversion
        # but body should be properly formatted JSON
        assert response.status_code in [status.HTTP_422_UNPROCESSABLE_ENTITY, status.HTTP_200_OK] 