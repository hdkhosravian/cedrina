import pytest
from fastapi.testclient import TestClient
from src.main import app
from src.domain.entities.user import User

def test_user_access_to_resource(client: TestClient, regular_user: User, regular_user_headers: dict):
    """Test user access to a regular resource."""
    # Test access to health endpoint - use follow_redirects=False to get the redirect status
    response = client.get("/api/v1/health", headers=regular_user_headers, follow_redirects=False)
    assert response.status_code == 307  # Health endpoint redirects

# Removed test_user_access_to_denied_resource - replaced by unit test in tests/unit/test_admin_access_denial.py
# which provides better isolation and doesn't interfere with feature test mocking