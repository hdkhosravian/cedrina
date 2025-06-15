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

def test_enforcer_initialization():
    """
    Test that the Casbin enforcer initializes correctly.

    This test ensures that the enforcer can be retrieved and is an instance of casbin.Enforcer, indicating that
    it has been properly initialized with the model and policy files. Failure to initialize could result from
    missing or malformed configuration files.

    Asserts:
        - The enforcer returned by get_enforcer() is an instance of casbin.Enforcer.
    """
    enforcer = get_enforcer()
    assert isinstance(enforcer, casbin.Enforcer), "Enforcer is not properly initialized"

def test_enforcer_policy_enforcement_admin_access():
    """
    Test that the enforcer allows access for an admin user to protected resources.

    This test verifies that the policies defined for the 'admin' role correctly grant access to specific
    resources such as '/health', '/metrics', '/docs', and '/redoc' for GET actions. This ensures that the
    enforcer is loading and applying policies as expected for authorized users.

    Asserts:
        - Access is granted for 'admin' to GET '/health', '/metrics', '/docs', and '/redoc'.
    """
    enforcer = get_enforcer()
    assert enforcer.enforce("admin", "/health", "GET"), "Admin should have access to /health"
    assert enforcer.enforce("admin", "/metrics", "GET"), "Admin should have access to /metrics"
    assert enforcer.enforce("admin", "/docs", "GET"), "Admin should have access to /docs"
    assert enforcer.enforce("admin", "/redoc", "GET"), "Admin should have access to /redoc"

def test_enforcer_policy_enforcement_non_admin_denied():
    """
    Test that the enforcer denies access for a non-admin user to protected resources.

    This test ensures that users without the 'admin' role (e.g., 'user') are denied access to protected resources
    such as '/health', '/metrics', '/docs', and '/redoc' for GET actions. This confirms that the enforcer
    correctly enforces a default-deny policy when no matching allow policy exists.

    Asserts:
        - Access is denied for 'user' to GET '/health', '/metrics', '/docs', and '/redoc'.
    """
    enforcer = get_enforcer()
    assert not enforcer.enforce("user", "/health", "GET"), "Non-admin should not have access to /health"
    assert not enforcer.enforce("user", "/metrics", "GET"), "Non-admin should not have access to /metrics"
    assert not enforcer.enforce("user", "/docs", "GET"), "Non-admin should not have access to /docs"
    assert not enforcer.enforce("user", "/redoc", "GET"), "Non-admin should not have access to /redoc"

def test_enforcer_invalid_subject():
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
    assert not enforcer.enforce("", "/health", "GET"), "Empty subject should not have access to /health"
    assert not enforcer.enforce("", "/metrics", "GET"), "Empty subject should not have access to /metrics"
    # Note: Casbin may handle None differently; test if applicable
    try:
        assert not enforcer.enforce(None, "/health", "GET"), "None subject should not have access to /health"
    except TypeError:
        pass  # Skip if Casbin raises TypeError for None 