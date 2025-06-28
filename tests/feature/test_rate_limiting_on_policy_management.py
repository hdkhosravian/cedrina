def test_rate_limiting_on_policy_management(client, admin_user_headers):
    headers = admin_user_headers
    # Step 1: Simulate exceeding rate limit (assuming 10 requests per minute)
    policy_data = {"subject": "user", "object": "/rate-limit-test", "action": "GET"}
    for _ in range(11):
        response = client.post("/api/v1/admin/policies/add", json=policy_data, headers=headers)
        if response.status_code == 429:
            break
    # ... existing code ...
