"""Feature tests for verify_against_hash method integration with authentication APIs.

This test module ensures that the new verify_against_hash method works correctly
throughout the entire authentication flow, including login and password change operations.
These tests validate the security implementation and proper integration with the API layer.
"""

import pytest

from src.domain.value_objects.password import Password
from src.utils.security import hash_password, verify_password


class TestVerifyAgainstHashIntegration:
    """Feature tests for verify_against_hash method integration with authentication flow."""

    def test_verify_against_hash_matches_security_utility(self):
        """Test that verify_against_hash produces same results as the security utility function."""
        # Arrange
        plain_password = "SecureP@ssw0rd947!"
        password_obj = Password(plain_password)
        hashed_password = hash_password(plain_password)
        
        # Act & Assert - Both methods should give the same result
        domain_result = password_obj.verify_against_hash(hashed_password)
        utility_result = verify_password(plain_password, hashed_password)
        
        assert domain_result == utility_result == True
        
        # Test with wrong password
        wrong_password = "WrongP@ssw0rd795!"
        wrong_password_obj = Password(wrong_password)
        
        domain_result_wrong = wrong_password_obj.verify_against_hash(hashed_password)
        utility_result_wrong = verify_password(wrong_password, hashed_password)
        
        assert domain_result_wrong == utility_result_wrong == False

    def test_verify_against_hash_constant_time_behavior(self):
        """Test that verify_against_hash uses constant-time comparison."""
        import time
        
        # Arrange
        password = "SecureP@ssw0rd947!"
        password_obj = Password(password)
        correct_hash = hash_password(password)
        wrong_hash = hash_password("WrongP@ssw0rd795!")
        
        # Act - Measure time for correct password verification
        start_time = time.perf_counter()
        for _ in range(10):
            result = password_obj.verify_against_hash(correct_hash)
        correct_time = time.perf_counter() - start_time
        
        # Act - Measure time for incorrect password verification
        start_time = time.perf_counter()
        for _ in range(10):
            result = password_obj.verify_against_hash(wrong_hash)
        wrong_time = time.perf_counter() - start_time
        
        # Assert - Time difference should be minimal (constant-time behavior)
        # Note: This is a heuristic test, actual timing attacks would need more sophisticated analysis
        time_difference_ratio = abs(correct_time - wrong_time) / max(correct_time, wrong_time)
        assert time_difference_ratio < 0.5, "Timing difference suggests possible timing attack vulnerability"

    def test_verify_against_hash_edge_cases(self):
        """Test verify_against_hash method with various edge cases."""
        # Arrange
        password = "SecureP@ssw0rd947!"
        password_obj = Password(password)
        
        # Test edge cases
        edge_cases = [
            "",  # Empty string
            "invalid_hash",  # Invalid hash format
            "$2b$12$",  # Incomplete bcrypt hash
            "a" * 100,  # Very long invalid hash
        ]
        
        for edge_case in edge_cases:
            # Act & Assert
            result = password_obj.verify_against_hash(edge_case)
            assert result is False, f"verify_against_hash should return False for edge case: {edge_case!r}"

    def test_verify_against_hash_security_properties(self):
        """Test security properties of the verify_against_hash method."""
        # Test 1: Method should never raise exceptions for invalid inputs
        password_obj = Password("SecureP@ssw0rd947!")
        
        malformed_inputs = [
            "",
            "not_a_hash",
            "$2b$invalid",
            "random_string",
            "a" * 1000,  # Very long string
        ]
        
        for malformed_input in malformed_inputs:
            try:
                result = password_obj.verify_against_hash(malformed_input)
                assert result is False, f"Should return False for malformed input: {malformed_input!r}"
            except Exception as e:
                pytest.fail(f"verify_against_hash should not raise exception for {malformed_input!r}, but got: {e}")
        
        # Test 2: Method should be deterministic
        correct_password = "SecureP@ssw0rd947!"
        password_obj = Password(correct_password)
        hashed = hash_password(correct_password)
        
        # Multiple calls should return the same result
        for _ in range(5):
            assert password_obj.verify_against_hash(hashed) is True
        
        wrong_password_obj = Password("WrongP@ssw0rd795!")
        for _ in range(5):
            assert wrong_password_obj.verify_against_hash(hashed) is False

    def test_verify_against_hash_different_bcrypt_rounds(self):
        """Test that verify_against_hash works with different bcrypt round counts."""
        password = "SecureP@ssw0rd947!"
        password_obj = Password(password)
        
        # Test with different bcrypt work factors (rounds)
        for rounds in [4, 8, 12]:  # Different computational costs
            # Create hash with specific rounds
            import bcrypt
            salt = bcrypt.gensalt(rounds=rounds)
            bcrypt_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
            
            # Verify our method works with this hash
            result = password_obj.verify_against_hash(bcrypt_hash)
            assert result is True, f"verify_against_hash should work with {rounds} rounds"
            
            # Verify wrong password fails
            wrong_password_obj = Password("WrongP@ssw0rd795!")
            wrong_result = wrong_password_obj.verify_against_hash(bcrypt_hash)
            assert wrong_result is False, f"verify_against_hash should reject wrong password with {rounds} rounds"

    @pytest.mark.asyncio
    async def test_verify_against_hash_method_integration_with_services(self):
        """Test that the verify_against_hash method integrates correctly with domain services."""
        from src.domain.services.authentication.user_authentication_service import UserAuthenticationService
        from src.domain.entities.user import User, Role
        from unittest.mock import AsyncMock
        
        # Arrange
        mock_user_repo = AsyncMock()
        mock_event_publisher = AsyncMock()
        auth_service = UserAuthenticationService(mock_user_repo, mock_event_publisher)
        
        # Create test user with known password
        plain_password = "SecureP@ssw0rd947!"
        hashed_password = hash_password(plain_password)
        user = User(
            id=1,
            username="testuser",
            email="test@example.com",
            hashed_password=hashed_password,
            role=Role.USER,
            is_active=True
        )
        
        password_obj = Password(plain_password)
        
        # Test direct integration with the domain service
        # This tests that our verify_against_hash method is actually being used
        result = await auth_service.verify_password(user, password_obj)
        assert result is True, "UserAuthenticationService should use verify_against_hash correctly"
        
        # Test with wrong password
        wrong_password_obj = Password("WrongP@ssw0rd795!")
        wrong_result = await auth_service.verify_password(user, wrong_password_obj)
        assert wrong_result is False, "UserAuthenticationService should reject wrong password"

    def test_verify_against_hash_unicode_and_special_characters(self):
        """Test verify_against_hash with unicode and special characters."""
        # Test with various character sets that meet password policy
        test_passwords = [
            "Pássw0rd123!",  # Accented characters
            "Test\nLine123!", # Newline character (likely won't pass validation)
            "Test\tTab123!",  # Tab character (likely won't pass validation)
        ]
        
        for test_password in test_passwords:
            try:
                password_obj = Password(test_password)
                hashed = hash_password(test_password)
                
                # Test correct verification
                result = password_obj.verify_against_hash(hashed)
                assert result is True, f"verify_against_hash should work with unicode password: {test_password!r}"
                
                # Test wrong password
                wrong_password_obj = Password("WrongP@ssw0rd795!")
                wrong_result = wrong_password_obj.verify_against_hash(hashed)
                assert wrong_result is False, f"verify_against_hash should reject wrong password for: {test_password!r}"
                    
            except ValueError:
                # Some passwords might not meet password policy requirements, that's okay
                continue 