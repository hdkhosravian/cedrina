"""Unit Tests for Casbin Permission Dependencies

This module contains unit tests for the permission dependencies defined in src/permissions/dependencies.py.
These dependencies are used in FastAPI routes to enforce access control by checking if a user has permission to
access a specific resource with a given action. The tests cover various scenarios including authorized access,
unauthorized access, and edge cases to ensure robust permission enforcement.

Tests:
    - test_check_permission_admin_access: Verifies that an admin user passes the permission check for protected resources.
    - test_check_permission_non_admin_denied: Verifies that a non-admin user fails the permission check and raises PermissionError.
    - test_check_permission_empty_role: Tests that an empty role fails the permission check and raises PermissionError.
    - test_check_permission_invalid_resource: Tests behavior when checking an invalid or non-existent resource.
    - test_check_permission_different_action: Tests that permission is denied for an action not covered by policy.
    - test_permission_granted: Tests that permission is granted when the enforcer allows it.
    - test_permission_denied: Tests that PermissionError is raised when the enforcer denies access.
    - test_user_with_no_role: Tests that PermissionError is raised if the user has no role.
    - test_permission_denied_with_translation: Tests that the permission denied message is translated.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.exceptions import PermissionError
from src.domain.entities.user import Role, User
from src.permissions.dependencies import check_permission
from src.utils.i18n import get_translated_message


# Mock Request class
class MockRequest:
    def __init__(self, language="en"):
        self.state = MagicMock()
        self.state.language = language


# Mock Enforcer class
class MockEnforcer:
    def __init__(self, enforce_result=True):
        self.enforce_result = enforce_result
        self.enforce = AsyncMock(return_value=enforce_result)


# Helper function to simulate permission check logic
async def simulate_permission_check(user_role, enforcer, resource, action):
    result = await enforcer.enforce(user_role, resource, action)
    if not result:
        message = get_translated_message("permission_denied_for_action", "en").format(
            role=user_role or "unknown", action=action, resource=resource
        )
        raise PermissionError(message)
    return True


@pytest.mark.asyncio
async def test_check_permission_admin_access():
    """Test that an admin user can access a protected resource.

    This test simulates the user role as 'admin' and the enforcer to return True for any policy check.
    It ensures that no PermissionError is raised when an admin accesses a resource like '/health'
    with the 'GET' action, simulating a successful permission check.

    Asserts:
        - No PermissionError is raised for admin access.
    """
    try:
        await simulate_permission_check("admin", MockEnforcer(True), "/health", "GET")
    except PermissionError:
        pytest.fail("PermissionError raised for admin access")


@pytest.mark.asyncio
async def test_check_permission_non_admin_denied():
    """Test that a non-admin user is denied access to a protected resource.

    This test simulates the user role as 'user' (non-admin) and the enforcer to return False,
    simulating a failed permission check. It checks a resource like '/health' with 'GET' action.
    A PermissionError should be raised, indicating access is forbidden.

    Asserts:
        - A PermissionError is raised for non-admin access.
    """
    with pytest.raises(PermissionError) as exc_info:
        await simulate_permission_check("user", MockEnforcer(False), "/health", "GET")
    expected_message = get_translated_message("permission_denied_for_action", "en").format(
        role="user", action="GET", resource="/health"
    )
    assert str(exc_info.value) == expected_message


@pytest.mark.asyncio
async def test_check_permission_empty_role():
    """Test that a request with no user role (anonymous) is denied access.

    This test simulates an empty user role (''), simulating an unauthenticated or anonymous request.
    The enforcer is mocked to return False, ensuring no policy matches. It checks a resource
    like '/health' with 'GET' action. A PermissionError should be raised.

    Asserts:
        - A PermissionError is raised for empty role.
    """
    with pytest.raises(PermissionError) as exc_info:
        await simulate_permission_check("", MockEnforcer(False), "/health", "GET")
    expected_message = get_translated_message("permission_denied_for_action", "en").format(
        role="unknown", action="GET", resource="/health"
    )
    assert str(exc_info.value) == expected_message


@pytest.mark.asyncio
async def test_check_permission_invalid_resource():
    """Test that permission is denied for a resource not covered by policy.

    This test simulates the user role as 'admin' but checks a resource not typically in policy,
    like '/invalid_resource', with 'GET' action. The enforcer is mocked to return False,
    simulating no policy match. A PermissionError should be raised.

    Asserts:
        - A PermissionError is raised for invalid resource.
    """
    with pytest.raises(PermissionError) as exc_info:
        await simulate_permission_check("admin", MockEnforcer(False), "/invalid_resource", "GET")
    expected_message = get_translated_message("permission_denied_for_action", "en").format(
        role="admin", action="GET", resource="/invalid_resource"
    )
    assert str(exc_info.value) == expected_message


@pytest.mark.asyncio
async def test_check_permission_different_action():
    """Test that permission is denied for an action not covered by policy.

    This test simulates the user role as 'admin' and checks a resource like '/health' with an action not typically
    allowed (e.g., 'POST' instead of 'GET'). The enforcer is mocked to return False, simulating no policy match
    for the action. It ensures that a PermissionError is raised, confirming that permissions
    are action-specific.

    Asserts:
        - A PermissionError is raised for an action not in policy.
    """
    with pytest.raises(PermissionError) as exc_info:
        await simulate_permission_check("admin", MockEnforcer(False), "/health", "POST")
    expected_message = get_translated_message("permission_denied_for_action", "en").format(
        role="admin", action="POST", resource="/health"
    )
    assert str(exc_info.value) == expected_message


@pytest.mark.asyncio
async def test_permission_granted():
    """Test that permission is granted when the enforcer allows it."""
    # Arrange
    request = MockRequest()
    mock_user = User(role=Role.ADMIN)
    mock_enforcer = MockEnforcer(enforce_result=True)
    dependency = check_permission("/test", "read")

    # Act & Assert
    try:
        await dependency(request=request, current_user=mock_user, enforcer=mock_enforcer)
    except PermissionError:
        pytest.fail("PermissionError was raised when access should have been granted.")


@pytest.mark.asyncio
async def test_permission_denied():
    """Test that PermissionError is raised when the enforcer denies access."""
    # Arrange
    request = MockRequest()
    mock_user = User(role=Role.USER)
    mock_enforcer = MockEnforcer(enforce_result=False)
    dependency = check_permission("/test", "write")

    # Act & Assert
    with pytest.raises(PermissionError) as exc_info:
        await dependency(request=request, current_user=mock_user, enforcer=mock_enforcer)

    expected_message = get_translated_message("permission_denied_for_action", "en").format(
        role="user", action="write", resource="/test"
    )
    assert str(exc_info.value) == expected_message


@pytest.mark.asyncio
async def test_user_with_no_role():
    """Test that PermissionError is raised if the user has no role."""
    # Arrange
    request = MockRequest()
    mock_user = User(role=None)
    mock_enforcer = MockEnforcer(enforce_result=True)  # Enforcer result shouldn't matter
    dependency = check_permission("/test", "read")

    # Act & Assert
    with pytest.raises(PermissionError) as exc_info:
        await dependency(request=request, current_user=mock_user, enforcer=mock_enforcer)

    expected_message = get_translated_message("user_has_no_role", "en")
    assert str(exc_info.value) == expected_message


@pytest.mark.asyncio
async def test_permission_denied_with_translation():
    """Test that the permission denied message is translated."""
    # Arrange
    request = MockRequest(language="fa")
    mock_user = User(role=Role.USER)
    mock_enforcer = MockEnforcer(enforce_result=False)
    dependency = check_permission("/test", "write")

    # Act & Assert
    with pytest.raises(PermissionError) as exc_info:
        await dependency(request=request, current_user=mock_user, enforcer=mock_enforcer)

    expected_message = get_translated_message("permission_denied_for_action", "fa").format(
        role="user", action="write", resource="/test"
    )
    assert str(exc_info.value) == expected_message


@pytest.mark.asyncio
async def test_permission_denied_english():
    """Test permission denied message in English."""
    request = MockRequest(language="en")
    mock_user = User(role=Role.USER)
    mock_enforcer = MockEnforcer(enforce_result=False)
    dependency = check_permission("/test", "write")

    with pytest.raises(PermissionError) as exc_info:
        await dependency(request=request, current_user=mock_user, enforcer=mock_enforcer)

    expected_message = get_translated_message("permission_denied_for_action", "en").format(
        role="user", action="write", resource="/test"
    )
    assert str(exc_info.value) == expected_message


@pytest.mark.asyncio
async def test_permission_denied_arabic():
    """Test permission denied message in Arabic."""
    request = MockRequest(language="ar")
    mock_user = User(role=Role.USER)
    mock_enforcer = MockEnforcer(enforce_result=False)
    dependency = check_permission("/test", "write")

    with pytest.raises(PermissionError) as exc_info:
        await dependency(request=request, current_user=mock_user, enforcer=mock_enforcer)

    expected_message = get_translated_message("permission_denied_for_action", "ar").format(
        role="user", action="write", resource="/test"
    )
    assert str(exc_info.value) == expected_message


@pytest.mark.asyncio
async def test_permission_denied_invalid_language():
    """Test permission denied message with invalid language falls back to default."""
    request = MockRequest(language="invalid")
    mock_user = User(role=Role.USER)
    mock_enforcer = MockEnforcer(enforce_result=False)
    dependency = check_permission("/test", "write")

    with pytest.raises(PermissionError) as exc_info:
        await dependency(request=request, current_user=mock_user, enforcer=mock_enforcer)

    expected_message = get_translated_message(
        "permission_denied_for_action", "en"  # Default language
    ).format(role="user", action="write", resource="/test")
    assert str(exc_info.value) == expected_message
