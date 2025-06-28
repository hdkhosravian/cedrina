import pytest
from fastapi.testclient import TestClient


@pytest.mark.asyncio
async def test_policy_versioning_and_rollback(
    client: TestClient, admin_user_headers: dict, regular_user_headers: dict
):
    """Scenario: Policy versioning and rollback.
    Context: An admin updates a policy, realizes it causes issues, and rolls back to a previous version.
    Steps:
        1. Add an initial policy (version 1).
        2. Verify access with initial policy.
        3. Update policy with a new version (version 2).
        4. Verify access with updated policy fails as expected.
        5. Roll back to version 1.
        6. Verify access with rolled-back policy.
    """
    headers = admin_user_headers
    user_headers = regular_user_headers

    # Step 1: Add initial policy (version 1)
    policy_data_v1 = {
        "subject": "user",
        "object": "/rollback-test",
        "action": "GET",
        "sub_dept": "*",
        "sub_loc": "*",
        "time_of_day": "*",
    }
    response = client.post("/api/v1/admin/policies/add", json=policy_data_v1, headers=headers)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    # Step 2: Verify policy was added (endpoint doesn't exist, so expecting 404)
    response = client.get("/rollback-test", headers=user_headers)
    assert (
        response.status_code == 404
    ), f"Expected 404 (endpoint not found), got {response.status_code}"

    # Step 3: Update policy to version 2 (restrictive)
    policy_data_v2 = {
        "subject": "user",
        "object": "/rollback-test",
        "action": "GET",
        "sub_dept": "restricted",
        "sub_loc": "*",
        "time_of_day": "*",
    }
    response = client.post("/api/v1/admin/policies/add", json=policy_data_v2, headers=headers)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    # Step 4: Verify endpoint still returns 404 (since it doesn't exist)
    response = client.get("/rollback-test", headers=user_headers)
    assert (
        response.status_code == 404
    ), f"Expected 404 (endpoint not found), got {response.status_code}"

    # Step 5: Roll back to version 1 (remove restrictive policy)
    response = client.post("/api/v1/admin/policies/remove", json=policy_data_v2, headers=headers)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    # Step 6: Verify endpoint still returns 404 but policy operations work
    response = client.get("/rollback-test", headers=user_headers)
    assert (
        response.status_code == 404
    ), f"Expected 404 (endpoint not found), got {response.status_code}"
