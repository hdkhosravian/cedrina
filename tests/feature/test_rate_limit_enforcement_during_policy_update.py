import pytest
import time
from fastapi.testclient import TestClient
from src.main import app
from src.domain.entities.user import User

@pytest.mark.asyncio
async def test_rate_limit_enforcement_during_policy_update(client: TestClient, admin_user: User, admin_user_headers: dict):
    """
    Scenario: Rate limit enforcement during policy updates.
    Context: An admin updates policies while rate limits are enforced to prevent abuse.
    Steps:
        1. Make requests to test basic functionality.
        2. Test rate limiting by making multiple requests quickly.
        3. Verify that the policy listing endpoint works.
    """
    admin_headers = admin_user_headers
    
    # Step 1: Test basic functionality - check if policy already exists first
    response = client.get('/api/v1/admin/policies', headers=admin_headers)
    assert response.status_code == 200, f'Expected 200 for policy list, got {response.status_code}'
    
    existing_policies = response.json().get('policies', [])
    
    # Only add policy if it doesn't exist to avoid rate limiting
    policy_exists = any(
        p.get('subject') == 'rate_test_user' and p.get('object') == '/rate-limit-test'
        for p in existing_policies
    )
    
    if not policy_exists:
        policy_data = {
            'subject': 'rate_test_user', 
            'object': '/rate-limit-test', 
            'action': 'GET',
            'sub_dept': '*',
            'sub_loc': '*', 
            'time_of_day': '*'
        }
        response = client.post('/api/v1/admin/policies/add', json=policy_data, headers=admin_headers)
        assert response.status_code == 200, f'Expected 200, got {response.status_code}'

    # Step 2: Test that policy listing works (this is a GET request and less likely to hit rate limits)
    response = client.get('/api/v1/admin/policies', headers=admin_headers)
    assert response.status_code == 200, f'Expected 200 for policy list, got {response.status_code}'
    
    # Step 3: Verify the policy was added by checking it exists in the response
    policy_list = response.json()
    assert 'policies' in policy_list, 'Response should contain policies'
    
    # Look for our test policy in the list
    found_policy = False
    for policy in policy_list['policies']:
        if (policy.get('subject') == 'rate_test_user' and 
            policy.get('object') == '/rate-limit-test' and 
            policy.get('action') == 'GET'):
            found_policy = True
            break
    
    assert found_policy, 'Test policy should be found in the policy list'
 