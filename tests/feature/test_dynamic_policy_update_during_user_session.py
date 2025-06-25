def test_dynamic_policy_update_during_user_session(client, regular_user_headers, admin_user_headers):
    user_headers = regular_user_headers
    admin_headers = admin_user_headers
    # ... existing code ... 

    # Step 1: Add initial policy allowing access
    initial_policy = {
        'subject': 'user',
        'object': '/dynamic-update-test',
        'action': 'GET'
    }
    response = client.post('/api/v1/admin/policies/add', json=initial_policy, headers=admin_headers)
    # ... existing code ...

    # Step 3: Update policy to deny access
    updated_policy = {
        'subject': 'user',
        'object': '/dynamic-update-test',
        'action': 'GET',
        'effect': 'deny'
    }
    response = client.post('/api/v1/admin/policies/add', json=updated_policy, headers=admin_headers)
    # ... existing code ... 