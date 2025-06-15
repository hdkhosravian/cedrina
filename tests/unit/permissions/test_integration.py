"""
Integration Tests for Casbin Permissions with API Endpoints

This module contains integration tests to verify that the Casbin permissions system correctly protects FastAPI
endpoints as defined in src/adapters/api/v1/. These tests simulate HTTP requests to protected endpoints with
different user roles to ensure that access control is enforced as expected. The tests cover successful access by
authorized users, denial for unauthorized users, and various edge cases.

Tests:
    - test_health_endpoint_admin_access: Verifies that an admin user can access the /health endpoint.
    - test_health_endpoint_non_admin_denied: Verifies that a non-admin user is denied access to the /health endpoint.
    - test_metrics_endpoint_admin_access: Verifies that an admin user can access the /metrics endpoint.
    - test_metrics_endpoint_non_admin_denied: Verifies that a non-admin user is denied access to the /metrics endpoint.
    - test_docs_endpoint_admin_access: Verifies that an admin user can access the /docs endpoint.
    - test_docs_endpoint_non_admin_denied: Verifies that a non-admin user is denied access to the /docs endpoint.
    - test_redoc_endpoint_admin_access: Verifies that an admin user can access the /redoc endpoint.
    - test_redoc_endpoint_non_admin_denied: Verifies that a non-admin user is denied access to the /redoc endpoint.
"""

import pytest
from fastapi.testclient import TestClient
from src.main import app
from src.permissions.dependencies import get_enforcer, get_current_user_role

# Mock class for Casbin Enforcer
class MockEnforcer:
    def __init__(self, enforce_result):
        self.enforce_result = enforce_result

    def enforce(self, *args):
        return self.enforce_result

@pytest.fixture
async def client():
    return TestClient(app)

@pytest.mark.asyncio
async def test_health_endpoint_access(client: TestClient):
    """
    Test access control for the /health endpoint.

    This test checks that:
    - An admin user (mocked role 'admin' with enforcer returning True) can access the endpoint (200 OK).
    - A non-admin user (mocked role 'user' with enforcer returning False) is denied access (403 Forbidden).

    Asserts:
        - Status code 200 for admin access to /health.
        - Status code 403 for non-admin access to /health.
    """
    # Override dependencies for admin access
    app.dependency_overrides[get_current_user_role] = lambda: lambda: 'admin'
    app.dependency_overrides[get_enforcer] = lambda: MockEnforcer(True)
    response = client.get('/api/v1/health')
    assert response.status_code == 200

    # Override dependencies for non-admin access
    app.dependency_overrides[get_current_user_role] = lambda: lambda: 'user'
    app.dependency_overrides[get_enforcer] = lambda: MockEnforcer(False)
    response = client.get('/api/v1/health')
    assert response.status_code == 403

    # Clear overrides after test
    app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_metrics_endpoint_access(client: TestClient):
    """
    Test access control for the /metrics endpoint.

    This test checks that:
    - An admin user (mocked role 'admin' with enforcer returning True) can access the endpoint (200 OK).
    - A non-admin user (mocked role 'user' with enforcer returning False) is denied access (403 Forbidden).

    Asserts:
        - Status code 200 for admin access to /metrics.
        - Status code 403 for non-admin access to /metrics.
    """
    # Override dependencies for admin access
    app.dependency_overrides[get_current_user_role] = lambda: lambda: 'admin'
    app.dependency_overrides[get_enforcer] = lambda: MockEnforcer(True)
    response = client.get('/api/v1/metrics')
    assert response.status_code == 200

    # Override dependencies for non-admin access
    app.dependency_overrides[get_current_user_role] = lambda: lambda: 'user'
    app.dependency_overrides[get_enforcer] = lambda: MockEnforcer(False)
    response = client.get('/api/v1/metrics')
    assert response.status_code == 403

    # Clear overrides after test
    app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_docs_endpoint_access(client: TestClient):
    """
    Test access control for the /docs endpoint.

    This test checks that:
    - An admin user (mocked role 'admin' with enforcer returning True) can access the endpoint (200 OK).
    - A non-admin user (mocked role 'user' with enforcer returning False) is denied access (403 Forbidden).

    Asserts:
        - Status code 200 for admin access to /docs.
        - Status code 403 for non-admin access to /docs.
    """
    # Override dependencies for admin access
    app.dependency_overrides[get_current_user_role] = lambda: lambda: 'admin'
    app.dependency_overrides[get_enforcer] = lambda: MockEnforcer(True)
    response = client.get('/api/v1/docs')
    assert response.status_code == 200

    # Override dependencies for non-admin access
    app.dependency_overrides[get_current_user_role] = lambda: lambda: 'user'
    app.dependency_overrides[get_enforcer] = lambda: MockEnforcer(False)
    response = client.get('/api/v1/docs')
    assert response.status_code == 403

    # Clear overrides after test
    app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_redoc_endpoint_access(client: TestClient):
    """
    Test access control for the /redoc endpoint.

    This test checks that:
    - An admin user (mocked role 'admin' with enforcer returning True) can access the endpoint (200 OK).
    - A non-admin user (mocked role 'user' with enforcer returning False) is denied access (403 Forbidden).

    Asserts:
        - Status code 200 for admin access to /redoc.
        - Status code 403 for non-admin access to /redoc.
    """
    # Override dependencies for admin access
    app.dependency_overrides[get_current_user_role] = lambda: lambda: 'admin'
    app.dependency_overrides[get_enforcer] = lambda: MockEnforcer(True)
    response = client.get('/api/v1/redoc')
    assert response.status_code == 200

    # Override dependencies for non-admin access
    app.dependency_overrides[get_current_user_role] = lambda: lambda: 'user'
    app.dependency_overrides[get_enforcer] = lambda: MockEnforcer(False)
    response = client.get('/api/v1/redoc')
    assert response.status_code == 403

    # Clear overrides after test
    app.dependency_overrides.clear() 