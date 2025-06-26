import pytest
from fastapi.testclient import TestClient

from src.main import app


@pytest.mark.asyncio
async def test_change_password_success_flow():
    """Full flow: register -> login -> change password -> login with new password."""
    client = TestClient(app)

    register_payload = {
        "username": "testchange",
        "email": "testchange@example.com",
        "password": "Oldpass123!",
    }
    response = client.post("/api/v1/auth/register", json=register_payload)
    assert response.status_code == 201
    login_payload = {
        "username": register_payload["username"],
        "password": register_payload["password"],
    }
    response = client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 200
    token = response.json()["tokens"]["access_token"]

    change_payload = {
        "current_password": register_payload["password"],
        "new_password": "Newpass123!",
    }
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/api/v1/auth/change-password", json=change_payload, headers=headers)
    assert response.status_code == 200

    # old password should fail
    response = client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 401

    login_payload["password"] = change_payload["new_password"]
    response = client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_change_password_wrong_current_password():
    """Attempt password change with incorrect current password."""
    client = TestClient(app)

    register_payload = {
        "username": "wrongcurrent",
        "email": "wrongcurrent@example.com",
        "password": "Oldpass123!",
    }
    response = client.post("/api/v1/auth/register", json=register_payload)
    assert response.status_code == 201

    login_payload = {
        "username": register_payload["username"],
        "password": register_payload["password"],
    }
    response = client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 200
    token = response.json()["tokens"]["access_token"]

    change_payload = {
        "current_password": "BadPass123!",
        "new_password": "Newpass123!",
    }
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/api/v1/auth/change-password", json=change_payload, headers=headers)
    assert response.status_code == 400
    assert "incorrect" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_change_password_invalid_new_password():
    """Attempt password change with invalid new password."""
    client = TestClient(app)

    register_payload = {
        "username": "invalidnew",
        "email": "invalidnew@example.com",
        "password": "Oldpass123!",
    }
    response = client.post("/api/v1/auth/register", json=register_payload)
    assert response.status_code == 201

    login_payload = {
        "username": register_payload["username"],
        "password": register_payload["password"],
    }
    response = client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 200
    token = response.json()["tokens"]["access_token"]

    change_payload = {
        "current_password": register_payload["password"],
        "new_password": "short",
    }
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/api/v1/auth/change-password", json=change_payload, headers=headers)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_change_password_new_password_missing_uppercase():
    """New password lacks an uppercase character and should be rejected."""
    client = TestClient(app)

    register_payload = {
        "username": "noupcase",
        "email": "noupcase@example.com",
        "password": "Oldpass123!",
    }
    response = client.post("/api/v1/auth/register", json=register_payload)
    assert response.status_code == 201

    login_payload = {
        "username": register_payload["username"],
        "password": register_payload["password"],
    }
    response = client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 200
    token = response.json()["tokens"]["access_token"]

    change_payload = {
        "current_password": register_payload["password"],
        "new_password": "lowercase123!",
    }
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/api/v1/auth/change-password", json=change_payload, headers=headers)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_change_password_unauthenticated():
    """Attempt password change without authentication token."""
    client = TestClient(app)

    change_payload = {
        "current_password": "whatever123",
        "new_password": "Another123!",
    }
    response = client.post("/api/v1/auth/change-password", json=change_payload)
    assert response.status_code == 401
