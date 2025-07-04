"""Tests for Error Standardization Service.

This test suite validates the error standardization service's ability to:
- Prevent information disclosure through consistent error responses
- Implement timing attack protection
- Provide consistent error messages regardless of failure reason
- Maintain security through standardized responses
"""

import asyncio
import time
import pytest
from unittest.mock import Mock, patch, AsyncMock

from src.domain.security.error_standardization import (
    ErrorStandardizationService,
    ErrorCategory,
    TimingPattern,
    StandardizedError,
    error_standardization_service
)


class TestErrorStandardizationService:
    """Test suite for ErrorStandardizationService functionality."""
    
    @pytest.fixture
    def error_service(self):
        """Create a fresh error standardization service for testing."""
        return ErrorStandardizationService()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_create_standardized_response_consistency(self, error_service):
        """Test that standardized responses are consistent regardless of actual error."""
        # Different actual errors should return the same standardized response
        response1 = await error_service.create_standardized_response(
            error_type="invalid_credentials",
            actual_error="User does not exist",
            correlation_id="test-123",
            language="en"
        )
        
        response2 = await error_service.create_standardized_response(
            error_type="user_not_found",  # Different error type
            actual_error="Invalid password",
            correlation_id="test-456",
            language="en"
        )
        
        # Both should map to the same authentication error
        assert response1["detail"] == response2["detail"]
        assert response1["error_code"] == response2["error_code"]
        assert response1["error_code"] == "AUTHENTICATION"
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_authentication_error_standardization(self, error_service):
        """Test that all authentication errors are standardized to prevent enumeration."""
        test_scenarios = [
            ("user_not_found", "user123", "User does not exist in database"),
            ("invalid_password", "admin", "Password hash does not match"),
            ("account_inactive", "testuser", "User account is disabled"),
            ("account_locked", "user456", "Account locked due to failed attempts"),
            ("expired_credentials", "olduser", "Password has expired")
        ]
        
        responses = []
        for failure_reason, username, actual_error in test_scenarios:
            response = await error_service.create_authentication_error_response(
                actual_failure_reason=failure_reason,
                username=username,
                correlation_id=f"test-{failure_reason}",
                language="en"
            )
            responses.append(response)
        
        # All responses should be identical to prevent enumeration
        first_response = responses[0]
        for response in responses[1:]:
            assert response["detail"] == first_response["detail"]
            assert response["error_code"] == first_response["error_code"]
            
        # Should contain generic message, not specific failure details
        assert "Invalid credentials provided" in first_response["detail"]
        assert "does not exist" not in first_response["detail"]
        assert "password" not in first_response["detail"].lower()
        assert "inactive" not in first_response["detail"]
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_timing_attack_prevention(self, error_service):
        """Test that standardized timing prevents timing attacks."""
        start_times = []
        end_times = []
        
        # Test multiple authentication failures with different underlying times
        for i in range(3):
            start_time = time.time()
            start_times.append(start_time)
            
            response = await error_service.create_authentication_error_response(
                actual_failure_reason="user_not_found" if i % 2 == 0 else "invalid_password",
                username=f"user{i}",
                correlation_id=f"test-{i}",
                request_start_time=start_time
            )
            
            end_times.append(time.time())
        
        # Calculate response times
        response_times = [end - start for start, end in zip(start_times, end_times)]
        
        # All response times should be similar (within reasonable variance)
        # due to standardized timing
        avg_time = sum(response_times) / len(response_times)
        for response_time in response_times:
            # Allow for some variance due to system load, but should be similar
            assert abs(response_time - avg_time) < 0.3  # 300ms variance tolerance
            
        # All should be at least the minimum timing for SLOW pattern (500ms)
        for response_time in response_times:
            assert response_time >= 0.4  # Allow for some system variance
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_timing_patterns(self, error_service):
        """Test different timing patterns are applied correctly."""
        # Mock timing to test pattern application
        with patch.object(error_service, '_apply_standard_timing') as mock_timing:
            mock_timing.return_value = asyncio.Future()
            mock_timing.return_value.set_result(None)
            
            # Test FAST timing pattern
            await error_service.create_standardized_response(
                error_type="invalid_input",
                correlation_id="test-fast"
            )
            
            # Should have been called with FAST pattern
            mock_timing.assert_called()
            call_args = mock_timing.call_args[0]
            assert call_args[0] == TimingPattern.FAST
            
            # Test SLOW timing pattern
            await error_service.create_standardized_response(
                error_type="invalid_credentials",
                correlation_id="test-slow"
            )
            
            # Should have been called with SLOW pattern
            call_args = mock_timing.call_args[0]
            assert call_args[0] == TimingPattern.SLOW
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_apply_standard_timing_calculations(self, error_service):
        """Test timing calculation logic."""
        # Test MEDIUM timing pattern
        start_time = time.time()
        await error_service._apply_standard_timing(
            TimingPattern.MEDIUM,
            correlation_id="test-123",
            request_start_time=start_time
        )
        elapsed = time.time() - start_time
        
        # Should be within MEDIUM timing range (200-400ms)
        min_time, max_time = error_service.TIMING_RANGES[TimingPattern.MEDIUM]
        target_time = (min_time + max_time) / 2
        assert elapsed >= target_time - 0.1  # Allow for execution overhead
        
        # Test VARIABLE timing with correlation ID
        start_time = time.time()
        await error_service._apply_standard_timing(
            TimingPattern.VARIABLE,
            correlation_id="test-deterministic",
            request_start_time=start_time
        )
        elapsed1 = time.time() - start_time
        
        # Same correlation ID should produce same timing
        start_time = time.time()
        await error_service._apply_standard_timing(
            TimingPattern.VARIABLE,
            correlation_id="test-deterministic",
            request_start_time=start_time
        )
        elapsed2 = time.time() - start_time
        
        # Should be similar timing for same correlation ID
        assert abs(elapsed1 - elapsed2) < 0.1
    
    @pytest.mark.unit
    def test_get_safe_error_message(self, error_service):
        """Test retrieval of safe, generic error messages."""
        # Test different error categories
        auth_msg = error_service.get_safe_error_message(ErrorCategory.AUTHENTICATION)
        authz_msg = error_service.get_safe_error_message(ErrorCategory.AUTHORIZATION)
        validation_msg = error_service.get_safe_error_message(ErrorCategory.VALIDATION)
        
        # Should return different messages for different categories
        assert auth_msg != authz_msg
        assert auth_msg != validation_msg
        
        # Should not contain specific technical details
        assert "password" not in auth_msg.lower()
        assert "user" not in auth_msg.lower()
        assert "database" not in auth_msg.lower()
        
        # Should be user-friendly generic messages
        assert "invalid" in auth_msg.lower() or "credentials" in auth_msg.lower()
        assert "access" in authz_msg.lower() or "denied" in authz_msg.lower()
    
    @pytest.mark.unit
    def test_log_error_safely(self, error_service):
        """Test that error logging masks sensitive information."""
        with patch.object(error_service, '_logger') as mock_logger:
            error_details = {
                "username": "sensitive_admin",
                "email": "admin@company.com",
                "password": "secretpassword123",
                "ip_address": "192.168.1.100",
                "other_field": "safe_value"
            }
            
            user_context = {
                "username": "sensitive_admin",
                "user_id": 12345,
                "role": "admin",
                "is_authenticated": True
            }
            
            error_service.log_error_safely(
                error_type="authentication_failure",
                error_details=error_details,
                correlation_id="test-123",
                user_context=user_context
            )
            
            # Should have logged the error
            mock_logger.error.assert_called_once()
            
            # Get the logged data
            call_args = mock_logger.error.call_args[1]
            
            # Sensitive fields should be hashed, not raw
            assert "username_hash" in call_args["error_details"]
            assert "email_hash" in call_args["error_details"]
            assert "password_hash" in call_args["error_details"]
            assert "ip_address_masked" in call_args["error_details"]
            
            # Raw sensitive values should not be present
            assert "sensitive_admin" not in str(call_args)
            assert "admin@company.com" not in str(call_args)
            assert "secretpassword123" not in str(call_args)
            assert "192.168.1.100" not in str(call_args)
            
            # Safe values should be preserved
            assert call_args["error_details"]["other_field"] == "safe_value"
            
            # User context should be sanitized
            assert call_args["user_context"]["user_id"] == 12345
            assert call_args["user_context"]["has_username"] is True
            assert "sensitive_admin" not in str(call_args["user_context"])
    
    @pytest.mark.unit
    def test_ip_masking(self, error_service):
        """Test IP address masking for privacy compliance."""
        test_cases = [
            ("192.168.1.100", "192.168.1.***"),
            ("10.0.0.1", "10.0.0.***"),
            ("172.16.254.1", "172.16.254.***"),
            ("127.0.0.1", "127.0.0.***"),
            ("invalid_ip", "invalid_***"),
            ("", "***")
        ]
        
        for ip, expected_pattern in test_cases:
            masked = error_service._mask_ip(ip)
            
            if ip == "":
                assert masked.endswith("***")
            elif "." in ip and len(ip.split(".")) == 4:
                assert masked == expected_pattern
            else:
                assert masked.endswith("***")
                assert len(masked) <= len(ip) + 3
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_response_structure_consistency(self, error_service):
        """Test that all error responses have consistent structure."""
        test_error_types = [
            "invalid_credentials",
            "insufficient_permissions",
            "invalid_input",
            "internal_error",
            "rate_limited"
        ]
        
        responses = []
        for error_type in test_error_types:
            response = await error_service.create_standardized_response(
                error_type=error_type,
                correlation_id=f"test-{error_type}"
            )
            responses.append(response)
        
        # All responses should have the same structure
        required_fields = {"detail", "error_code", "timestamp"}
        for response in responses:
            assert set(response.keys()) >= required_fields
            
            # Error codes should be uppercase category names
            assert response["error_code"].isupper()
            assert response["error_code"] in [
                "AUTHENTICATION", "AUTHORIZATION", "VALIDATION", "SYSTEM", "RATE_LIMIT"
            ]
            
            # Should have ISO timestamp
            assert "T" in response["timestamp"]
            assert "Z" in response["timestamp"] or "+" in response["timestamp"]
    
    @pytest.mark.unit
    def test_standard_error_definitions(self, error_service):
        """Test that standard error definitions are properly configured."""
        standard_errors = error_service.STANDARD_ERRORS
        
        # Should have all authentication errors mapping to same generic response
        auth_errors = ["invalid_credentials", "user_not_found", "inactive_account", "locked_account"]
        auth_message_keys = set()
        for error_type in auth_errors:
            if error_type in standard_errors:
                auth_message_keys.add(standard_errors[error_type].message_key)
        
        # All auth errors should use the same message key
        assert len(auth_message_keys) == 1
        assert "invalid_credentials_generic" in auth_message_keys
        
        # All auth errors should have SLOW timing to prevent timing attacks
        for error_type in auth_errors:
            if error_type in standard_errors:
                assert standard_errors[error_type].timing_pattern == TimingPattern.SLOW
                assert standard_errors[error_type].http_status == 401
    
    @pytest.mark.unit
    def test_global_service_instance(self):
        """Test that global service instance is properly configured."""
        assert error_standardization_service is not None
        assert isinstance(error_standardization_service, ErrorStandardizationService)
        
        # Should have proper timing ranges configured
        assert TimingPattern.FAST in error_standardization_service.TIMING_RANGES
        assert TimingPattern.SLOW in error_standardization_service.TIMING_RANGES
        
        # Timing ranges should be reasonable
        fast_range = error_standardization_service.TIMING_RANGES[TimingPattern.FAST]
        slow_range = error_standardization_service.TIMING_RANGES[TimingPattern.SLOW]
        
        assert fast_range[0] < fast_range[1]  # Valid range
        assert slow_range[0] < slow_range[1]  # Valid range
        assert fast_range[1] < slow_range[0]  # Fast should be faster than slow
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_correlation_id_handling(self, error_service):
        """Test that correlation IDs are properly handled in responses."""
        correlation_id = "test-correlation-12345"
        
        response = await error_service.create_standardized_response(
            error_type="invalid_credentials",
            correlation_id=correlation_id
        )
        
        assert response["correlation_id"] == correlation_id
        
        # Without correlation ID, should not include the field
        response_no_corr = await error_service.create_standardized_response(
            error_type="invalid_credentials"
        )
        
        assert "correlation_id" not in response_no_corr
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_language_support(self, error_service):
        """Test that different languages are supported in error responses."""
        # This would require actual translation support
        # For now, test that language parameter is accepted
        response_en = await error_service.create_standardized_response(
            error_type="invalid_credentials",
            language="en"
        )
        
        response_es = await error_service.create_standardized_response(
            error_type="invalid_credentials",
            language="es"
        )
        
        # Both should succeed and have detail field
        assert "detail" in response_en
        assert "detail" in response_es
        
        # Structure should be the same
        assert response_en.keys() == response_es.keys() 