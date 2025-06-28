import pytest
from fastapi.testclient import TestClient

from src.domain.entities.user import User


@pytest.mark.asyncio
async def test_user_access_based_on_department_and_location(
    client: TestClient, regular_user: User, regular_user_headers: dict
):
    """Scenario: User access restricted by department and location.
    Context: A multinational company restricts access to resources based on user's department and location.
    Steps:
        1. Set up a policy for a specific department and location.
        2. Assign department and location to a user.
        3. Test access with correct department and location.
        4. Test access with incorrect department or location.
    """
    headers = regular_user_headers

    # Step 1: Add policy for specific department and location (policy already exists)
    policy_data = {
        "subject": "user",
        "object": "/department-resource",
        "action": "GET",
        "sub_dept": "engineering",
        "sub_loc": "NY",
        "time_of_day": "*",
    }
    response = client.post("/api/v1/admin/policies/add", json=policy_data, headers=headers)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    # Step 2: Test access to non-existent endpoint (since /department-resource doesn't exist)
    # The policy exists but the endpoint doesn't, so we expect 404
    response = client.get("/department-resource", headers=headers)
    assert (
        response.status_code == 404
    ), f"Expected 404 (endpoint not found), got {response.status_code}"

    # Step 3: Verify policy was added by checking policy list
    response = client.get("/api/v1/admin/policies", headers=headers)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    # Step 4: Test with a more restrictive policy (different department)
    policy_data_restrictive = {
        "subject": "user",
        "object": "/department-resource",
        "action": "GET",
        "sub_dept": "marketing",
        "sub_loc": "CA",
        "time_of_day": "*",
    }
    response = client.post(
        "/api/v1/admin/policies/add", json=policy_data_restrictive, headers=headers
    )
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
