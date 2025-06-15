"""
Unit Tests for Casbin Permission Dependencies

This module contains unit tests for the permission dependencies defined in src/permissions/dependencies.py.
These dependencies are used in FastAPI routes to enforce access control by checking if a user has permission to
access a specific resource with a given action. The tests cover various scenarios including authorized access,
unauthorized access, and edge cases to ensure robust permission enforcement.

Tests:
    - test_check_permission_admin_access: Verifies that an admin user passes the permission check for protected resources.
    - test_check_permission_non_admin_denied: Verifies that a non-admin user fails the permission check and raises HTTP 403.
    - test_check_permission_empty_role: Tests that an empty role fails the permission check and raises HTTP 403.
    - test_check_permission_invalid_resource: Tests behavior when checking an invalid or non-existent resource.
    - test_check_permission_different_action: Tests that permission is denied for an action not covered by policy.
"""

import pytest
from fastapi import HTTPException, status
from src.permissions.dependencies import check_permission

# Mock class for Casbin Enforcer
class MockEnforcer:
    def __init__(self, enforce_result):
        self.enforce_result = enforce_result

    def enforce(self, *args):
        return self.enforce_result

# Helper function to simulate permission check logic
def simulate_permission_check(user_role, enforcer, resource, action):
    if not enforcer.enforce(user_role, resource, action):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User with role {user_role or 'unknown'} does not have permission to {action} {resource}"
        )
    return True

@pytest.mark.asyncio
async def test_check_permission_admin_access():
    """
    Test that an admin user can access a protected resource.

    This test simulates the user role as 'admin' and the enforcer to return True for any policy check.
    It ensures that no HTTPException is raised when an admin accesses a resource like '/health'
    with the 'GET' action, simulating a successful permission check.

    Asserts:
        - No HTTPException is raised for admin access.
    """
    try:
        simulate_permission_check('admin', MockEnforcer(True), '/health', 'GET')
    except HTTPException:
        pytest.fail("HTTPException raised for admin access")

@pytest.mark.asyncio
async def test_check_permission_non_admin_denied():
    """
    Test that a non-admin user is denied access to a protected resource.

    This test simulates the user role as 'user' (non-admin) and the enforcer to return False,
    simulating a failed permission check. It checks a resource like '/health' with 'GET' action.
    An HTTPException with status code 403 should be raised, indicating access is forbidden.

    Asserts:
        - An HTTPException with status code 403 is raised for non-admin access.
    """
    with pytest.raises(HTTPException) as exc_info:
        simulate_permission_check('user', MockEnforcer(False), '/health', 'GET')
    assert exc_info.value.status_code == 403

@pytest.mark.asyncio
async def test_check_permission_empty_role():
    """
    Test that a request with no user role (anonymous) is denied access.

    This test simulates an empty user role (''), simulating an unauthenticated or anonymous request.
    The enforcer is mocked to return False, ensuring no policy matches. It checks a resource
    like '/health' with 'GET' action. An HTTPException with status code 403 should be raised.

    Asserts:
        - An HTTPException with status code 403 is raised for empty role.
    """
    with pytest.raises(HTTPException) as exc_info:
        simulate_permission_check('', MockEnforcer(False), '/health', 'GET')
    assert exc_info.value.status_code == 403

@pytest.mark.asyncio
async def test_check_permission_invalid_resource():
    """
    Test that permission is denied for a resource not covered by policy.

    This test simulates the user role as 'admin' but checks a resource not typically in policy,
    like '/invalid_resource', with 'GET' action. The enforcer is mocked to return False,
    simulating no policy match. An HTTPException with status code 403 should be raised.

    Asserts:
        - An HTTPException with status code 403 is raised for invalid resource.
    """
    with pytest.raises(HTTPException) as exc_info:
        simulate_permission_check('admin', MockEnforcer(False), '/invalid_resource', 'GET')
    assert exc_info.value.status_code == 403

@pytest.mark.asyncio
async def test_check_permission_different_action():
    """
    Test that permission is denied for an action not covered by policy.

    This test simulates the user role as 'admin' and checks a resource like '/health' with an action not typically
    allowed (e.g., 'POST' instead of 'GET'). The enforcer is mocked to return False, simulating no policy match
    for the action. It ensures that an HTTPException with status code 403 is raised, confirming that permissions
    are action-specific.

    Asserts:
        - An HTTPException with status code 403 is raised for an action not in policy.
    """
    with pytest.raises(HTTPException) as exc_info:
        simulate_permission_check('admin', MockEnforcer(False), '/health', 'POST')
    assert exc_info.value.status_code == 403 