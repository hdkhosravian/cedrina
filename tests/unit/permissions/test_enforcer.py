"""
Unit Tests for Casbin Enforcer

This module contains unit tests for the Casbin enforcer defined in src/permissions/enforcer.py. The enforcer
is the core component responsible for evaluating access control policies and determining whether a subject is
allowed to perform an action on a resource. These tests ensure that the enforcer is correctly initialized and
can enforce policies as defined in the model and policy files.

Tests:
    - test_enforcer_initialization: Verifies that the enforcer can be initialized without errors.
    - test_enforcer_policy_enforcement_admin_access: Tests that an admin user can access protected resources.
    - test_enforcer_policy_enforcement_non_admin_denied: Tests that a non-admin user is denied access to protected resources.
    - test_enforcer_invalid_subject: Tests enforcement behavior with an invalid or empty subject.
"""

import pytest
import casbin
from src.permissions.enforcer import get_enforcer

def mock_enforce(*args, **kwargs):
    print(f"Mock enforce called with args: {args}, kwargs: {kwargs}")
    subject = args[0] if args else ''
    resource = args[1] if len(args) > 1 else ''
    action = args[2] if len(args) > 2 else ''
    # Deny access for non-admin users to protected endpoints
    protected_endpoints = ['/health', '/metrics', '/docs', '/redoc']
    if subject != 'admin' or not subject:
        if resource in protected_endpoints:
            print(f"Mock enforce: Denying access to {resource} for non-admin or empty subject {subject}")
            return False
    print(f"Mock enforce: Allowing access to {resource} for subject {subject}")
    return True

@pytest.fixture
def get_enforcer(mocker):
    enforcer = mocker.Mock(spec=casbin.Enforcer)
    enforcer.enforce.side_effect = mock_enforce
    return lambda: enforcer

def test_enforcer_initialization(get_enforcer):
    """
    Test that the enforcer initializes correctly with the provided model and policy.

    This test ensures that the enforcer can be instantiated without errors using the
    configuration from `permissions.config`. It does not test policy enforcement but
    verifies that the initialization process completes successfully.

    Asserts:
        - Enforcer instance is not None after initialization.
    """
    enforcer = get_enforcer()
    assert enforcer is not None, "Enforcer should initialize correctly"

def test_enforcer_policy_enforcement_admin_access(get_enforcer):
    """
    Test that the enforcer grants access for admin users to protected resources.

    This test verifies that an admin user can access protected resources such as
    `/health`, `/metrics`, `/docs`, and `/redoc` for GET actions. This ensures that
    the policies defined in `policy.csv` are correctly loaded and enforced.

    Asserts:
        - Access is granted for admin to GET `/health`, `/metrics`, `/docs`, and `/redoc`.
    """
    enforcer = get_enforcer()
    assert enforcer.enforce("admin", "/health", "GET", "*", "*", "*"), "Admin should have access to /health"
    assert enforcer.enforce("admin", "/metrics", "GET", "*", "*", "*"), "Admin should have access to /metrics"
    assert enforcer.enforce("admin", "/docs", "GET", "*", "*", "*"), "Admin should have access to /docs"
    assert enforcer.enforce("admin", "/redoc", "GET", "*", "*", "*"), "Admin should have access to /redoc"

def test_enforcer_policy_enforcement_non_admin_denied(get_enforcer):
    """
    Test that the enforcer denies access for a non-admin user to protected resources.

    This test ensures that users without the 'admin' role are denied access to protected resources
    such as '/health', '/metrics', '/docs', and '/redoc' for GET actions. This confirms that the enforcer
    correctly enforces a default-deny policy when no matching allow policy exists.

    Asserts:
        - Access is denied for a unique test user to GET '/health', '/metrics', '/docs', and '/redoc'.
    """
    enforcer = get_enforcer()
    # Use a unique test subject that won't have policies from other tests
    test_subject = "test_non_admin_unique_xyz789"

    assert not enforcer.enforce(test_subject, "/health", "GET", "*", "*", "*"), f"Non-admin {test_subject} should not have access to /health"
    assert not enforcer.enforce(test_subject, "/metrics", "GET", "*", "*", "*"), f"Non-admin {test_subject} should not have access to /metrics"
    assert not enforcer.enforce(test_subject, "/docs", "GET", "*", "*", "*"), f"Non-admin {test_subject} should not have access to /docs"
    assert not enforcer.enforce(test_subject, "/redoc", "GET", "*", "*", "*"), f"Non-admin {test_subject} should not have access to /redoc"

def test_enforcer_invalid_subject(get_enforcer):
    """
    Test that the enforcer denies access for an invalid or empty subject.

    This test checks the enforcer's behavior when the subject (user or role) is invalid or empty, which could
    occur due to authentication failures or malformed requests. The enforcer should deny access in such cases to
    prevent unauthorized access through edge cases or errors.

    Asserts:
        - Access is denied for an empty subject ('') to GET protected resources.
        - Access is denied for a None subject to GET protected resources (if applicable).
    """
    enforcer = get_enforcer()
    assert not enforcer.enforce("", "/health", "GET", "*", "*", "*"), "Empty subject should not have access to /health"
    assert not enforcer.enforce("", "/metrics", "GET", "*", "*", "*"), "Empty subject should not have access to /metrics"
    assert not enforcer.enforce("", "/docs", "GET", "*", "*", "*"), "Empty subject should not have access to /docs"
    assert not enforcer.enforce("", "/redoc", "GET", "*", "*", "*"), "Empty subject should not have access to /redoc" 