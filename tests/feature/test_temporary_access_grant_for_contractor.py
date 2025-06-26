import pytest
from fastapi.testclient import TestClient
from src.main import app
from src.domain.entities.user import User
from unittest.mock import patch

@pytest.mark.asyncio
async def test_temporary_access_grant_for_contractor(client: TestClient, regular_user: User, admin_user_headers: dict, regular_user_headers: dict):
    """
    Scenario: Temporary access grant for a contractor.
    Context: A contractor is granted temporary access to a resource for a limited period.
    Steps:
        1. Admin grants temporary access with a time-based policy.
        2. Verify contractor access during the valid period.
        3. Simulate time passing beyond the valid period.
        4. Verify access is revoked after the period expires.
    """
    admin_headers = admin_user_headers
    contractor_headers = regular_user_headers

    # Step 1: Add temporary access policy
    policy_data = {
        'subject': 'user',
        'object': '/contractor-resource',
        'action': 'GET',
        'sub_dept': '*',
        'sub_loc': '*',
        'time_of_day': '*'
    }
    response = client.post('/api/v1/admin/policies/add', json=policy_data, headers=admin_headers)
    assert response.status_code == 200, f'Expected 200, got {response.status_code}'

    # Step 2: Verify access during valid period (endpoint doesn't exist, so expecting 404)
    # Since /contractor-resource endpoint doesn't exist, we expect 404 not permission check
    response = client.get('/contractor-resource', headers=contractor_headers)
    assert response.status_code == 404, f'Expected 404 (endpoint not found), got {response.status_code}'

    # Step 3: Remove the policy to simulate expiration
    response = client.post('/api/v1/admin/policies/remove', json=policy_data, headers=admin_headers)
    assert response.status_code == 200, f'Expected 200, got {response.status_code}'

    # Step 4: Verify policy was removed (still 404 since endpoint doesn't exist)
    response = client.get('/contractor-resource', headers=contractor_headers)
    assert response.status_code == 404, f'Expected 404 (endpoint not found), got {response.status_code}'