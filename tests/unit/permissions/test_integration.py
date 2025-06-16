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
    - test_expired_token_handling: Verifies that an expired token results in a 401 Unauthorized response.
    - test_openapi_json_endpoint_admin_access: Verifies that an admin user can access the /openapi.json endpoint.
    - test_openapi_json_endpoint_non_admin_denied: Verifies that a non-admin user is denied access to the /openapi.json endpoint.
    - test_policy_enforcement_for_wrong_role: Verifies that a user with a valid but incorrect role is denied access with a 403 error.
"""

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta

from src.main import app
from src.core.dependencies.auth import get_current_user
from src.domain.entities.user import User, Role
from src.permissions.dependencies import get_enforcer
from src.core.exceptions import AuthenticationError

# Mock User Fixtures
@pytest.fixture
def mock_admin_user():
    """Provides a mock active admin user."""
    user = MagicMock(spec=User)
    user.id = 1
    user.role = Role.ADMIN
    user.is_active = True
    return user

@pytest.fixture
def mock_normal_user():
    """Provides a mock active normal user."""
    user = MagicMock(spec=User)
    user.id = 2
    user.role = Role.USER
    user.is_active = True
    return user

@pytest.fixture
def mock_inactive_user():
    """Provides a mock inactive user."""
    user = MagicMock(spec=User)
    user.id = 3
    user.role = Role.ADMIN
    user.is_active = False
    return user

# Mock Enforcer
class MockEnforcer:
    """A mock Casbin enforcer that checks against a predefined set of policies."""
    def __init__(self, policies):
        self.policies = policies

    def enforce(self, sub, obj, act):
        # The role is passed as an enum, so we get its value
        return (sub, obj, act) in self.policies

@pytest.fixture
def client():
    """
    Test client fixture that sets up a mock enforcer with default admin policies
    and clears dependency overrides after the test.
    """
    policies = {
        ("admin", "/health", "GET"),
        ("admin", "/metrics", "GET"),
        ("admin", "/docs", "GET"),
        ("admin", "/redoc", "GET"),
        ("admin", "/openapi.json", "GET"),
    }
    app.dependency_overrides[get_enforcer] = lambda: MockEnforcer(policies)
    yield TestClient(app)
    app.dependency_overrides.clear()

# Reusable test function to check endpoint access
def check_endpoint_access(client, method, url, user, expected_status):
    """Helper function to test endpoint access for a given user."""
    app.dependency_overrides[get_current_user] = lambda: user
    # Add a dummy token to satisfy the oauth2_scheme
    headers = {"Authorization": "Bearer fake-token"}
    response = client.request(method, url, headers=headers)
    assert response.status_code == expected_status
    return response

# --- Test Cases ---

@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", [
    "/api/v1/health", 
    "/api/v1/metrics", 
    "/docs", 
    "/redoc", 
    "/openapi.json"
])
async def test_admin_access_to_protected_endpoints(client, mock_admin_user, endpoint):
    """Tests that an admin user has access to all protected routes."""
    check_endpoint_access(client, "get", endpoint, mock_admin_user, 200)

@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", [
    "/api/v1/health", 
    "/api/v1/metrics", 
    "/docs", 
    "/redoc", 
    "/openapi.json"
])
async def test_normal_user_denied_access_to_protected_endpoints(client, mock_normal_user, endpoint):
    """
    Tests that a normal user is denied access to all protected routes with a 
    403 Forbidden error and a specific permission error message.
    """
    response = check_endpoint_access(client, "get", endpoint, mock_normal_user, 403)
    # Strip the /api/v1 prefix for the error message assertion if present
    expected_resource = endpoint.replace("/api/v1", "")
    assert f"User with role 'user' does not have permission to GET {expected_resource}" in response.json()["detail"]

@pytest.mark.asyncio
async def test_access_with_inactive_user(client, mock_inactive_user):
    """
    Tests that an inactive user is denied access at the authentication layer,
    even if they have an admin role.
    """
    async def override_get_inactive_user():
        if not mock_inactive_user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        return mock_inactive_user

    app.dependency_overrides[get_current_user] = override_get_inactive_user
    headers = {"Authorization": "Bearer fake-token-for-inactive-user"}
    response = client.get("/api/v1/health", headers=headers)
    assert response.status_code == 401
    assert "User not found or inactive" in response.text

@pytest.mark.asyncio
async def test_unauthorized_access_without_token(client):
    """Tests that requests without an Authorization header receive a 401 response."""
    response = client.get("/api/v1/health")
    assert response.status_code == 401
    assert "Not authenticated" in response.text

@pytest.mark.asyncio
async def test_user_with_no_role_is_denied(client):
    """Tests that a user with a null/None role is gracefully denied access with a 403 error."""
    user_no_role = MagicMock(spec=User)
    user_no_role.id = 4
    user_no_role.role = None
    user_no_role.is_active = True
    response = check_endpoint_access(client, "get", "/api/v1/health", user_no_role, 403)
    assert "User has no assigned role" in response.json()["detail"]

@pytest.mark.asyncio
async def test_policy_enforcement_for_wrong_role(client):
    """
    Tests that a user with a valid role but incorrect for the endpoint (e.g., 'finance' trying to access
    an 'admin' resource) is properly denied with a 403 error.
    This simulates a real-world scenario where policies in policy.csv are the deciding factor.
    """
    # Mock a role enum for the test
    mock_role = MagicMock()
    mock_role.value = "finance"

    finance_user = MagicMock(spec=User)
    finance_user.id = 5
    finance_user.role = mock_role  # A role that exists but doesn't have access
    finance_user.is_active = True

    # The policies fixture in client only allows 'admin' for this endpoint
    response = check_endpoint_access(client, "get", "/api/v1/health", finance_user, 403)

    # Verify the specific error message from the Casbin enforcer
    assert "User with role 'finance' does not have permission to GET /health" in response.json()["detail"]

@pytest.mark.asyncio
async def test_expired_token_handling(client):
    """Tests that an expired token results in a 401 Unauthorized response."""
    async def override_get_expired_token():
        raise AuthenticationError("Token has expired")

    app.dependency_overrides[get_current_user] = override_get_expired_token
    headers = {"Authorization": "Bearer expired-token"}
    response = client.get("/api/v1/health", headers=headers)
    assert response.status_code == 401
    assert "Token has expired" in response.json()["detail"]

@pytest.mark.asyncio
async def test_invalid_token_format(client):
    """Tests that an invalid token format results in a 401 Unauthorized response."""
    headers = {"Authorization": "InvalidFormat token"}
    response = client.get("/api/v1/health", headers=headers)
    assert response.status_code == 401
    assert "Not authenticated" in response.text

@pytest.mark.asyncio
async def test_role_change_during_session(client, mock_admin_user, mock_normal_user):
    """Tests that role changes during a session are properly enforced."""
    # First access as admin
    check_endpoint_access(client, "get", "/api/v1/health", mock_admin_user, 200)
    
    # Change role to normal user
    check_endpoint_access(client, "get", "/api/v1/health", mock_normal_user, 403)

@pytest.mark.asyncio
async def test_concurrent_access_attempts(client, mock_admin_user, mock_normal_user):
    """Tests that concurrent access attempts are properly handled."""
    import asyncio
    
    async def access_endpoint(user):
        return check_endpoint_access(client, "get", "/api/v1/health", user, 200 if user.role == Role.ADMIN else 403)
    
    # Simulate concurrent access attempts
    tasks = [
        access_endpoint(mock_admin_user),
        access_endpoint(mock_normal_user),
        access_endpoint(mock_admin_user)
    ]
    
    results = await asyncio.gather(*tasks)
    assert results[0].status_code == 200  # Admin access
    assert results[1].status_code == 403  # Normal user denied
    assert results[2].status_code == 200  # Admin access

@pytest.mark.asyncio
async def test_malformed_token_handling(client):
    """Tests that malformed tokens are properly handled."""
    headers = {"Authorization": "Bearer malformed.token.here"}
    response = client.get("/api/v1/health", headers=headers)
    assert response.status_code == 401
    assert "Invalid token" in response.text

@pytest.mark.asyncio
async def test_token_with_invalid_signature(client):
    """Tests that tokens with invalid signatures are properly handled."""
    headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}
    response = client.get("/api/v1/health", headers=headers)
    assert response.status_code == 401
    assert "Invalid token" in response.text

@pytest.mark.asyncio
async def test_openapi_json_endpoint_admin_access(client, mock_admin_user):
    """Tests that an admin user can access the /openapi.json endpoint."""
    check_endpoint_access(client, "get", "/openapi.json", mock_admin_user, 200)

@pytest.mark.asyncio
async def test_openapi_json_endpoint_non_admin_denied(client, mock_normal_user):
    """Tests that a non-admin user is denied access to the /openapi.json endpoint."""
    response = check_endpoint_access(client, "get", "/openapi.json", mock_normal_user, 403)
    assert "does not have permission" in response.json()["detail"] 