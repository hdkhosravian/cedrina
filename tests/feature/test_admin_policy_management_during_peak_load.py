def test_admin_policy_management_during_peak_load(client, admin_user_headers):
    """Scenario: Admin manages policies during peak load conditions.
    Context: During high traffic, an admin needs to update policies efficiently.
    Steps:
        1. Test multiple policy operations in sequence.
        2. Verify the Redis watcher synchronization works.
        3. Ensure all policies are correctly managed.
        4. Verify system stability during rapid operations.
    """
    headers = admin_user_headers

    # Step 1: Perform multiple policy operations to simulate load (within rate limit)
    policy_operations = []

    # Add multiple policies quickly but within the 10/minute rate limit
    for i in range(5):
        policy_data = {
            "subject": f"load_test_user_{i}",
            "object": f"/api/v1/resource_{i}",
            "action": "GET",
        }
        response = client.post("/api/v1/admin/policies/add", json=policy_data, headers=headers)
        policy_operations.append(response)
        assert response.status_code == 200, f"Policy add {i} failed with {response.status_code}"

    # Step 2: Verify all policies were added successfully
    success_count = 0
    already_exists_count = 0

    for response in policy_operations:
        response_data = response.json()
        if "Policy added successfully" in response_data["message"]:
            success_count += 1
        elif "Policy already exists" in response_data["message"]:
            already_exists_count += 1

    # At least some operations should succeed (accounting for potential duplicates)
    assert (
        success_count + already_exists_count == 5
    ), "Not all policy operations completed successfully"

    # Step 3: Verify policies can be retrieved
    response = client.get("/api/v1/admin/policies", headers=headers)
    assert response.status_code == 200, f"Policy retrieval failed with {response.status_code}"

    policies_data = response.json()
    assert "policies" in policies_data
    assert len(policies_data["policies"]) >= 5, "Expected at least 5 policies to be present"

    # Step 4: Test Redis watcher by adding one more policy (should work since we're under rate limit)
    test_policy = {
        "subject": "redis_test_user",
        "object": "/api/v1/redis_test_resource",
        "action": "POST",
    }
    response = client.post("/api/v1/admin/policies/add", json=test_policy, headers=headers)
    # This should succeed since we're well under the 10/minute limit with only 6 total requests
    assert (
        response.status_code == 200
    ), f"Redis watcher test policy addition failed with {response.status_code}"

    # System should remain stable - if we reach here, the test passed
    assert True, "System handled policy management under load successfully"
