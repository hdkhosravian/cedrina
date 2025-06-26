def test_abac_with_time_based_access(client, regular_user_headers, admin_user_headers):
    user_headers = regular_user_headers
    admin_headers = admin_user_headers
    
    # Step 1: Add policy with time restriction using ABAC attributes
    policy_data = {
        'subject': 'user',
        'object': '/api/v1/test-resource',
        'action': 'GET',
        'time_of_day': 'working_hours'
    }
    response = client.post('/api/v1/admin/policies/add', json=policy_data, headers=admin_headers)
    assert response.status_code == 200, f'Expected 200, got {response.status_code}'
    
    # Verify the response contains the expected policy details
    response_data = response.json()
    assert response_data['subject'] == 'user'
    assert response_data['object'] == '/api/v1/test-resource'
    assert response_data['action'] == 'GET'
    assert response_data['attributes']['time_of_day'] == 'working_hours'
    # Policy might already exist from previous test runs
    assert 'Policy added successfully' in response_data['message'] or 'Policy already exists' in response_data['message']
    
    # Step 2: Verify the policy can be retrieved
    response = client.get('/api/v1/admin/policies', headers=admin_headers)
    assert response.status_code == 200, f'Expected 200, got {response.status_code}'
    
    policies_data = response.json()
    assert 'policies' in policies_data
    
    # Check that our ABAC policy exists in the list
    added_policy = None
    for policy in policies_data['policies']:
        if (policy['subject'] == 'user' and 
            policy['object'] == '/api/v1/test-resource' and 
            policy['action'] == 'GET' and
            policy.get('attributes', {}).get('time_of_day') == 'working_hours'):
            added_policy = policy
            break
    
    assert added_policy is not None, "ABAC policy with time_of_day attribute was not found in policy list"