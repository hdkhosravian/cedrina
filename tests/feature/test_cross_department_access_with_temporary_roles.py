def test_cross_department_access_with_temporary_roles(
    client, regular_user_headers, admin_user_headers
):
    user_headers = regular_user_headers
    admin_headers = admin_user_headers
    # ... existing code ...

    # Step 1: Add policy for temporary role
    policy_data = {
        "subject": "temp_manager",
        "object": "/cross-dept-resource",
        "action": "GET",
        "valid_until": "2025-12-31T23:59:59Z",
    }
    response = client.post("/api/v1/admin/policies/add", json=policy_data, headers=admin_headers)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    # ... existing code ...
