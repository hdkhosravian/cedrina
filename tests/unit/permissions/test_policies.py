"""
Unit Tests for Casbin Policy Management

This module contains unit tests for the policy management functions defined in src/permissions/policies.py.
These functions allow dynamic addition and removal of access control policies at runtime, enabling flexible
permission updates without modifying static policy files. The tests cover policy addition, removal, duplicate
handling, and edge cases to ensure reliable policy management.

Tests:
    - test_add_policy_success: Verifies that a new policy can be added successfully.
    - test_add_policy_duplicate: Tests behavior when adding a policy that already exists.
    - test_remove_policy_success: Verifies that an existing policy can be removed successfully.
    - test_remove_policy_nonexistent: Tests behavior when attempting to remove a policy that does not exist.
    - test_add_and_remove_policy_cycle: Tests the full cycle of adding a policy, verifying access, removing it, and verifying denial.
"""

import pytest
from src.permissions.policies import add_policy, remove_policy
from src.permissions.enforcer import get_enforcer

def test_add_policy_success():
    """
    Test that a new policy can be added successfully.

    This test attempts to add a new policy granting a test role access to a test resource with a specific action.
    It ensures that the policy is added successfully by checking the return value of add_policy. A successful
    addition indicates that the policy was not already present and has been incorporated into the enforcer's
    in-memory policy set.

    Asserts:
        - add_policy returns True when a new policy is added successfully.
    """
    result = add_policy("test_role", "/test_resource", "GET")
    assert result, "Adding a new policy should return True"

def test_add_policy_duplicate():
    """
    Test behavior when adding a policy that already exists.

    This test first adds a policy for a test role and resource, then attempts to add the same policy again. It
    checks the behavior of add_policy when a duplicate policy is provided. Casbin typically returns False for
    duplicate policies since no change is made to the policy set.

    Asserts:
        - add_policy returns True for the first addition.
        - add_policy returns False for a duplicate policy addition.
    """
    # First addition
    result1 = add_policy("test_role_duplicate", "/test_resource_duplicate", "GET")
    assert result1, "First policy addition should return True"
    
    # Duplicate addition
    result2 = add_policy("test_role_duplicate", "/test_resource_duplicate", "GET")
    assert not result2, "Duplicate policy addition should return False"

def test_remove_policy_success():
    """
    Test that an existing policy can be removed successfully.

    This test first adds a policy to ensure it exists, then attempts to remove it. It checks that the removal
    operation returns True, indicating that the policy was found and successfully removed from the enforcer's
    in-memory policy set.

    Asserts:
        - add_policy returns True for policy addition.
        - remove_policy returns True when removing an existing policy.
    """
    # Add policy first
    add_result = add_policy("test_role_remove", "/test_resource_remove", "GET")
    assert add_result, "Policy addition before removal should return True"
    
    # Remove policy
    remove_result = remove_policy("test_role_remove", "/test_resource_remove", "GET")
    assert remove_result, "Removing an existing policy should return True"

def test_remove_policy_nonexistent():
    """
    Test behavior when attempting to remove a policy that does not exist.

    This test attempts to remove a policy for a subject, resource, and action combination that has not been added.
    It checks that remove_policy returns False, indicating that no policy was found to remove. This ensures that
    the function handles non-existent policies gracefully.

    Asserts:
        - remove_policy returns False when attempting to remove a non-existent policy.
    """
    result = remove_policy("test_role_nonexistent", "/test_resource_nonexistent", "GET")
    assert not result, "Removing a non-existent policy should return False"

def test_add_and_remove_policy_cycle():
    """
    Test the full cycle of adding a policy, verifying access, removing it, and verifying denial.

    This test performs a complete cycle of policy management:
    1. Adds a policy granting a test role access to a test resource.
    2. Verifies that the enforcer allows access based on the new policy.
    3. Removes the policy.
    4. Verifies that access is now denied after policy removal.

    This ensures that policy changes are immediately reflected in enforcement decisions, which is critical for
    dynamic access control in a running application.

    Asserts:
        - Policy addition returns True.
        - Enforcer allows access after policy addition.
        - Policy removal returns True.
        - Enforcer denies access after policy removal.
    """
    subject = "test_role_cycle"
    resource = "/test_resource_cycle"
    action = "GET"
    
    # Step 1: Add policy
    add_result = add_policy(subject, resource, action)
    assert add_result, "Policy addition in cycle should return True"
    
    # Step 2: Verify access granted
    enforcer = get_enforcer()
    assert enforcer.enforce(subject, resource, action), "Access should be granted after policy addition"
    
    # Step 3: Remove policy
    remove_result = remove_policy(subject, resource, action)
    assert remove_result, "Policy removal in cycle should return True"
    
    # Step 4: Verify access denied
    assert not enforcer.enforce(subject, resource, action), "Access should be denied after policy removal" 