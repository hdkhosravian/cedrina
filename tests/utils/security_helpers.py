"""
Security testing helper utilities.

This module provides reusable components for testing security patterns
throughout the application. These helpers ensure consistent security
testing and make it easy to validate security requirements.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from jose import jwt

from src.core.config.settings import settings
from src.domain.entities.user import User, Role
from src.core.exceptions import AuthenticationError
from src.utils.i18n import get_translated_message


class SecurityTestHelpers:
    """
    Collection of helper methods for security testing.
    
    These methods provide standardized ways to create test scenarios,
    validate security patterns, and ensure consistent testing across
    the application.
    """

    @staticmethod
    def create_test_user(user_id: int, username: str = None, email: str = None) -> User:
        """
        Create a test user with consistent defaults.
        
        Args:
            user_id: Unique user identifier
            username: Optional username (defaults to test_user_{id})
            email: Optional email (defaults to test{id}@example.com)
            
        Returns:
            User entity for testing
        """
        username = username or f"test_user_{user_id}"
        email = email or f"test{user_id}@example.com"
        
        return User(
            id=user_id,
            username=username,
            email=email,
            role=Role.USER,
            is_active=True
        )

    @staticmethod
    def create_jwt_token(
        user: User,
        jti: str = None,
        exp_delta: timedelta = None,
        issuer: str = None,
        audience: str = None,
        additional_claims: Dict[str, Any] = None
    ) -> str:
        """
        Create a JWT token with configurable claims for testing.
        
        Args:
            user: User for whom to create the token
            jti: JWT ID (defaults to random value)
            exp_delta: Expiration time delta (defaults to 7 days)
            issuer: Token issuer (defaults to configured issuer)
            audience: Token audience (defaults to configured audience)
            additional_claims: Additional claims to include
            
        Returns:
            Encoded JWT token string
        """
        jti = jti or f"test-jti-{user.id}"
        exp_delta = exp_delta or timedelta(days=7)
        issuer = issuer or settings.JWT_ISSUER
        audience = audience or settings.JWT_AUDIENCE
        additional_claims = additional_claims or {}
        
        payload = {
            "sub": str(user.id),
            "jti": jti,
            "exp": datetime.now(timezone.utc) + exp_delta,
            "iat": datetime.now(timezone.utc),
            "iss": issuer,
            "aud": audience,
            **additional_claims
        }
        
        return jwt.encode(payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256")

    @staticmethod
    def create_malformed_token() -> str:
        """Create a malformed JWT token for testing error handling."""
        return "not.a.valid.jwt.token"

    @staticmethod
    def create_expired_token(user: User, days_ago: int = 1) -> str:
        """
        Create an expired JWT token for testing temporal validation.
        
        Args:
            user: User for whom to create the token
            days_ago: How many days ago the token expired
            
        Returns:
            Expired JWT token string
        """
        return SecurityTestHelpers.create_jwt_token(
            user=user,
            jti=f"expired-{user.id}",
            exp_delta=timedelta(days=-days_ago)
        )

    @staticmethod
    def create_wrong_issuer_token(user: User, malicious_issuer: str = "https://evil.com") -> str:
        """
        Create a token with wrong issuer for testing issuer validation.
        
        Args:
            user: User for whom to create the token
            malicious_issuer: Malicious issuer to use
            
        Returns:
            JWT token with wrong issuer
        """
        return SecurityTestHelpers.create_jwt_token(
            user=user,
            jti=f"wrong-issuer-{user.id}",
            issuer=malicious_issuer
        )

    @staticmethod
    def create_wrong_audience_token(user: User, wrong_audience: str = "wrong-audience") -> str:
        """
        Create a token with wrong audience for testing audience validation.
        
        Args:
            user: User for whom to create the token
            wrong_audience: Wrong audience to use
            
        Returns:
            JWT token with wrong audience
        """
        return SecurityTestHelpers.create_jwt_token(
            user=user,
            jti=f"wrong-audience-{user.id}",
            audience=wrong_audience
        )

    @staticmethod
    async def validate_token_ownership_pattern(
        token: str, 
        current_user: User, 
        language: str = "en"
    ) -> Dict[str, Any]:
        """
        Reference implementation of secure token ownership validation.
        
        This method implements the security pattern documented in
        docs/authentication/security_fixes.md and should be used
        as a template for similar validation in endpoints.
        
        Args:
            token: JWT token to validate
            current_user: Currently authenticated user
            language: Language for error messages
            
        Returns:
            Decoded token payload
            
        Raises:
            AuthenticationError: If validation fails
        """
        try:
            payload = jwt.decode(
                token,
                settings.JWT_PUBLIC_KEY,
                algorithms=["RS256"],
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE
            )
            token_user_id = int(payload["sub"])
            
            # CRITICAL: Validate that token belongs to authenticated user
            if token_user_id != current_user.id:
                raise AuthenticationError(get_translated_message("invalid_token", language))
                
            return payload
            
        except jwt.JWTError as e:
            raise AuthenticationError(get_translated_message("invalid_token", language)) from e

    @staticmethod
    def assert_cross_user_attack_prevented(
        primary_user: User,
        other_user: User,
        token_validation_func,
        create_token_func = None
    ):
        """
        Helper to assert that cross-user attacks are prevented.
        
        This is a reusable test pattern for validating that endpoints
        properly reject tokens from other users.
        
        Args:
            primary_user: User who should be authenticated
            other_user: User whose token should be rejected
            token_validation_func: Function that validates token ownership
            create_token_func: Optional function to create tokens
        """
        create_token_func = create_token_func or SecurityTestHelpers.create_jwt_token
        
        # Create token for other_user
        other_user_token = create_token_func(other_user)
        
        # Validate with primary_user should fail
        try:
            token_validation_func(other_user_token, primary_user)
            assert False, "Expected AuthenticationError but validation succeeded"
        except AuthenticationError:
            pass  # Expected behavior
        except Exception as e:
            assert False, f"Expected AuthenticationError but got {type(e).__name__}: {e}"


class SecurityTestScenarios:
    """
    Common security test scenarios that can be reused across different test modules.
    
    These scenarios provide standardized ways to test security requirements
    and ensure consistent validation across the application.
    """

    @staticmethod
    def get_token_validation_test_cases(user: User) -> Dict[str, Dict[str, Any]]:
        """
        Get standard test cases for token validation testing.
        
        Args:
            user: User for creating test tokens
            
        Returns:
            Dictionary of test case names mapped to test case data
        """
        return {
            "valid_token": {
                "token": SecurityTestHelpers.create_jwt_token(user),
                "should_pass": True,
                "description": "Valid token should pass validation"
            },
            "malformed_token": {
                "token": SecurityTestHelpers.create_malformed_token(),
                "should_pass": False,
                "description": "Malformed token should be rejected"
            },
            "expired_token": {
                "token": SecurityTestHelpers.create_expired_token(user),
                "should_pass": False,
                "description": "Expired token should be rejected"
            },
            "wrong_issuer": {
                "token": SecurityTestHelpers.create_wrong_issuer_token(user),
                "should_pass": False,
                "description": "Token with wrong issuer should be rejected"
            },
            "wrong_audience": {
                "token": SecurityTestHelpers.create_wrong_audience_token(user),
                "should_pass": False,
                "description": "Token with wrong audience should be rejected"
            }
        }

    @staticmethod
    def get_cross_user_test_scenario(user_one: User, user_two: User) -> Dict[str, Any]:
        """
        Get cross-user attack test scenario.
        
        Args:
            user_one: Primary user who should be authenticated
            user_two: Other user whose token should be rejected
            
        Returns:
            Test scenario data
        """
        return {
            "primary_user": user_one,
            "other_user": user_two,
            "other_user_token": SecurityTestHelpers.create_jwt_token(user_two),
            "description": "Cross-user token should be rejected"
        }


class SecurityAssertions:
    """
    Custom assertions for security testing.
    
    These assertions provide clear, reusable ways to validate
    security requirements in tests.
    """

    @staticmethod
    def assert_authentication_error_raised(func, *args, **kwargs):
        """
        Assert that an AuthenticationError is raised.
        
        Args:
            func: Function to test
            *args: Arguments to pass to function
            **kwargs: Keyword arguments to pass to function
        """
        try:
            func(*args, **kwargs)
            assert False, "Expected AuthenticationError to be raised"
        except AuthenticationError:
            pass  # Expected
        except Exception as e:
            assert False, f"Expected AuthenticationError but got {type(e).__name__}: {e}"

    @staticmethod
    def assert_secure_logging(log_capture, expected_event: str, expected_fields: Dict[str, Any] = None):
        """
        Assert that security events are properly logged.
        
        Args:
            log_capture: Log capture fixture
            expected_event: Expected log event message
            expected_fields: Expected fields in log entry
        """
        expected_fields = expected_fields or {}
        
        # Find log entries that match the expected event
        matching_entries = [
            entry for entry in log_capture.entries
            if expected_event in entry.get("event", "")
        ]
        
        assert len(matching_entries) > 0, f"Expected log event '{expected_event}' not found"
        
        # Validate expected fields if provided
        if expected_fields:
            for field_name, expected_value in expected_fields.items():
                assert field_name in matching_entries[0], f"Expected field '{field_name}' not found in log"
                assert matching_entries[0][field_name] == expected_value, \
                    f"Field '{field_name}' has value '{matching_entries[0][field_name]}', expected '{expected_value}'"

    @staticmethod
    def assert_consistent_error_response(response_one, response_two):
        """
        Assert that error responses are consistent to prevent information disclosure.
        
        Args:
            response_one: First error response
            response_two: Second error response
        """
        assert response_one.status_code == response_two.status_code, \
            "Error responses should have consistent status codes"
        
        # Both should be authentication errors
        assert response_one.status_code == 401, "Expected 401 Unauthorized status"
        
        # Error messages should be generic and not reveal specifics
        error_one = response_one.json().get("detail", "")
        error_two = response_two.json().get("detail", "")
        
        # Both should contain generic error message
        assert "Invalid" in error_one or "Authentication" in error_one, \
            "Error message should be generic"
        assert "Invalid" in error_two or "Authentication" in error_two, \
            "Error message should be generic" 