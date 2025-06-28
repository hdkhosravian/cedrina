"""Unit Tests for Policy Management Service

This module contains unit tests for the PolicyService class, ensuring that dynamic
policy management functions correctly and securely with ABAC and audit logging.
"""

from unittest.mock import MagicMock

import pytest
from casbin import Enforcer

from src.core.exceptions import PermissionError
from src.domain.services.auth.policy import PolicyService


@pytest.fixture
def mock_enforcer():
    """Fixture to create a mock Casbin Enforcer instance.

    Returns:
        MagicMock: A mock of the Casbin Enforcer.

    """
    return MagicMock(spec=Enforcer)


@pytest.fixture
def policy_service(mock_enforcer):
    """Fixture to create a PolicyService instance with a mock enforcer.

    Args:
        mock_enforcer: The mock Casbin Enforcer instance.

    Returns:
        PolicyService: The policy service instance for testing.

    """
    return PolicyService(mock_enforcer)


class TestPolicyService:
    """Test suite for PolicyService class."""

    def test_add_policy_success(self, policy_service, mock_enforcer):
        """Test successful addition of a policy.

        Args:
            policy_service: The PolicyService instance.
            mock_enforcer: The mock Casbin Enforcer instance.

        """
        mock_enforcer.add_policy.return_value = True
        result = policy_service.add_policy(
            "admin", "/test", "GET", "user_123", "192.168.1.1", "Mozilla/5.0", None, "en"
        )
        assert result is True
        mock_enforcer.add_policy.assert_called_once_with("admin", "/test", "GET", "*", "*", "*")

    def test_add_policy_with_attributes_success(self, policy_service, mock_enforcer):
        """Test successful addition of a policy with ABAC attributes.

        Args:
            policy_service: The PolicyService instance.
            mock_enforcer: The mock Casbin Enforcer instance.

        """
        mock_enforcer.add_policy.return_value = True
        attributes = {"sub_dept": "engineering", "sub_loc": "NY", "time_of_day": "day"}
        result = policy_service.add_policy(
            "admin", "/test", "GET", "user_123", "192.168.1.1", "Mozilla/5.0", attributes, "en"
        )
        assert result is True
        mock_enforcer.add_policy.assert_called_once_with(
            "admin", "/test", "GET", "engineering", "NY", "day"
        )

    def test_add_policy_already_exists(self, policy_service, mock_enforcer):
        """Test adding a policy that already exists.

        Args:
            policy_service: The PolicyService instance.
            mock_enforcer: The mock Casbin Enforcer instance.

        """
        mock_enforcer.add_policy.return_value = False
        result = policy_service.add_policy(
            "admin", "/test", "GET", "user_123", "192.168.1.1", "Mozilla/5.0", None, "en"
        )
        assert result is False
        mock_enforcer.add_policy.assert_called_once_with("admin", "/test", "GET", "*", "*", "*")

    def test_add_policy_invalid_input(self, policy_service):
        """Test adding a policy with invalid input.

        Args:
            policy_service: The PolicyService instance.

        """
        with pytest.raises(PermissionError) as exc_info:
            policy_service.add_policy(
                "", "/test", "GET", "user_123", "192.168.1.1", "Mozilla/5.0", None, "en"
            )
        assert "policy_add_failed" in str(exc_info.value)

    def test_add_policy_invalid_wildcard(self, policy_service):
        """Test adding a policy with invalid wildcard in subject.

        Args:
            policy_service: The PolicyService instance.

        """
        with pytest.raises(PermissionError) as exc_info:
            policy_service.add_policy(
                "*", "/test", "GET", "user_123", "192.168.1.1", "Mozilla/5.0", None, "en"
            )
        assert "policy_add_failed" in str(exc_info.value)

    def test_remove_policy_success(self, policy_service, mock_enforcer):
        """Test successful removal of a policy.

        Args:
            policy_service: The PolicyService instance.
            mock_enforcer: The mock Casbin Enforcer instance.

        """
        mock_enforcer.remove_policy.return_value = True
        result = policy_service.remove_policy(
            "admin", "/test", "GET", "user_123", "192.168.1.1", "Mozilla/5.0", "en"
        )
        assert result is True
        mock_enforcer.remove_policy.assert_called_once_with("admin", "/test", "GET")

    def test_remove_policy_not_found(self, policy_service, mock_enforcer):
        """Test removing a policy that does not exist.

        Args:
            policy_service: The PolicyService instance.
            mock_enforcer: The mock Casbin Enforcer instance.

        """
        mock_enforcer.remove_policy.return_value = False
        result = policy_service.remove_policy(
            "admin", "/test", "GET", "user_123", "192.168.1.1", "Mozilla/5.0", "en"
        )
        assert result is False
        mock_enforcer.remove_policy.assert_called_once_with("admin", "/test", "GET")

    def test_remove_policy_invalid_input(self, policy_service):
        """Test removing a policy with invalid input.

        Args:
            policy_service: The PolicyService instance.

        """
        with pytest.raises(PermissionError) as exc_info:
            policy_service.remove_policy(
                "", "/test", "GET", "user_123", "192.168.1.1", "Mozilla/5.0", "en"
            )
        assert "policy_remove_failed" in str(exc_info.value)

    def test_get_policies_success(self, policy_service, mock_enforcer):
        """Test successful retrieval of policies.

        Args:
            policy_service: The PolicyService instance.
            mock_enforcer: The mock Casbin Enforcer instance.

        """
        mock_enforcer.get_policy.return_value = [
            ["admin", "/health", "GET"],
            ["admin", "/metrics", "GET"],
        ]
        policies = policy_service.get_policies("en")
        assert len(policies) == 2

        # Check that policies are returned as dictionaries with correct structure
        expected_policies = [
            {"subject": "admin", "object": "/health", "action": "GET"},
            {"subject": "admin", "object": "/metrics", "action": "GET"},
        ]
        for expected_policy in expected_policies:
            assert expected_policy in policies

        mock_enforcer.get_policy.assert_called_once()

    def test_get_policies_empty(self, policy_service, mock_enforcer):
        """Test retrieval of policies when none exist.

        Args:
            policy_service: The PolicyService instance.
            mock_enforcer: The mock Casbin Enforcer instance.

        """
        mock_enforcer.get_policy.return_value = []
        policies = policy_service.get_policies("en")
        assert len(policies) == 0
        mock_enforcer.get_policy.assert_called_once()
