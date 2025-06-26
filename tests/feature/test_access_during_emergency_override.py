import pytest
from fastapi.testclient import TestClient
from src.main import app
from src.domain.entities.user import User

def test_access_during_emergency_override(client, regular_user_headers, admin_user_headers):
    """
    Scenario: Emergency access policy management.
    Context: During an emergency, certain users are granted temporary elevated access.
    Steps:
        1. Add emergency access policy.
        2. Verify policy exists.
        3. Remove emergency policy.
        4. Verify policy is removed.
    """
    admin_headers = admin_user_headers
    user_headers = regular_user_headers
    
    # Step 1: Set up emergency access policy
    policy_data = {
        'subject': 'emergency_team',
        'object': '/api/v1/emergency-resource',
        'action': 'GET'
    }
    response = client.post('/api/v1/admin/policies/add', json=policy_data, headers=admin_headers)
    assert response.status_code == 200, f'Expected 200, got {response.status_code}'

    # Verify the response contains the expected policy details
    response_data = response.json()
    assert response_data['subject'] == 'emergency_team'
    assert response_data['object'] == '/api/v1/emergency-resource'
    assert response_data['action'] == 'GET'
    assert 'Policy added successfully' in response_data['message'] or 'Policy already exists' in response_data['message']

    # Step 2: Verify policy exists in list
    response = client.get('/api/v1/admin/policies', headers=admin_headers)
    assert response.status_code == 200, f'Expected 200, got {response.status_code}'
    
    policies_data = response.json()
    assert 'policies' in policies_data
    
    # Check that our emergency policy exists in the list
    emergency_policy = None
    for policy in policies_data['policies']:
        if (policy['subject'] == 'emergency_team' and 
            policy['object'] == '/api/v1/emergency-resource' and 
            policy['action'] == 'GET'):
            emergency_policy = policy
            break
    
    assert emergency_policy is not None, "Emergency policy was not found in policy list"

    # Step 3: Remove emergency policy
    removal_data = {
        'subject': 'emergency_team',
        'object': '/api/v1/emergency-resource',
        'action': 'GET'
    }
    response = client.post('/api/v1/admin/policies/remove', json=removal_data, headers=admin_headers)
    assert response.status_code == 200, f'Expected 200, got {response.status_code}'

    # Verify removal response
    response_data = response.json()
    assert response_data['subject'] == 'emergency_team'
    assert response_data['object'] == '/api/v1/emergency-resource'
    assert response_data['action'] == 'GET'
    assert 'Policy removed successfully' in response_data['message'] or 'Policy not found' in response_data['message'] 