from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

from src.main import app
from src.domain.entities.user import User, Role
from src.core.exceptions import AuthenticationError


def _setup_mocks(mocker, *, user=None):
    if user is None:
        user = User(id=1, username="test", email="t@example.com", role=Role.USER, is_active=True)
    user_service_mock = AsyncMock()
    user_service_mock.register_user.return_value = user
    user_service_mock.authenticate_by_credentials.return_value = user
    mocker.patch(
        "src.adapters.api.v1.auth.dependencies.get_user_auth_service",
        return_value=user_service_mock,
    )

    token_service_mock = AsyncMock()
    token_service_mock.create_access_token.return_value = "access"
    token_service_mock.create_refresh_token.return_value = "refresh"
    token_service_mock.validate_token.return_value = {"jti": "abc", "sub": user.id}
    mocker.patch(
        "src.adapters.api.v1.auth.dependencies.get_token_service",
        return_value=token_service_mock,
    )

    mocker.patch("src.core.dependencies.auth.get_current_user", return_value=user)
    return token_service_mock


def _login_and_get_tokens(client):
    signup_payload = {
        "username": "test",
        "email": "t@example.com",
        "password": "Password123!",
    }
    assert client.post("/api/v1/auth/register", json=signup_payload).status_code == 201

    login_resp = client.post(
        "/api/v1/auth/login",
        data={"username": "test", "password": "Password123!"},
    )
    assert login_resp.status_code == 200
    return login_resp.json()["tokens"]


def test_logout_revokes_tokens_step_by_step(mocker):
    """Full logout flow: sign up -> login -> logout."""

    client = TestClient(app)
    token_service_mock = _setup_mocks(mocker)

    tokens = _login_and_get_tokens(client)

    logout_resp = client.delete(
        "/api/v1/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )

    assert logout_resp.status_code == 200
    assert logout_resp.json()["message"] == "Logged out successfully"
    token_service_mock.validate_token.assert_called_once_with("access")
    token_service_mock.revoke_access_token.assert_awaited_once_with("abc")
    token_service_mock.revoke_refresh_token.assert_awaited_once_with("refresh")


def test_logout_invalid_refresh_token(mocker):
    """Logout with an invalid refresh token should return 401."""

    client = TestClient(app)
    token_service_mock = _setup_mocks(mocker)
    token_service_mock.revoke_refresh_token.side_effect = AuthenticationError("Invalid refresh token")
    tokens = _login_and_get_tokens(client)

    resp = client.delete(
        "/api/v1/auth/logout",
        json={"refresh_token": "bad"},
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )

    assert resp.status_code == 401
    assert "Invalid refresh token" in resp.json()["detail"]


def test_logout_missing_authorization_header(mocker):
    """Missing access token should trigger authentication error."""

    client = TestClient(app)
    _setup_mocks(mocker)
    tokens = _login_and_get_tokens(client)

    resp = client.delete(
        "/api/v1/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert resp.status_code == 401
    assert resp.json()["detail"] == "Not authenticated"


def test_logout_invalid_access_token(mocker):
    """Invalid access token should be rejected."""

    client = TestClient(app)
    token_service_mock = _setup_mocks(mocker)
    token_service_mock.validate_token.side_effect = AuthenticationError("bad token")
    tokens = _login_and_get_tokens(client)

    resp = client.delete(
        "/api/v1/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
        headers={"Authorization": "Bearer bad"},
    )

    assert resp.status_code == 401
    assert "bad token" in resp.json()["detail"]


def test_logout_payload_validation_error(mocker):
    """Sending no refresh_token should result in 422."""

    client = TestClient(app)
    _setup_mocks(mocker)
    _login_and_get_tokens(client)

    resp = client.delete(
        "/api/v1/auth/logout",
        json={},
        headers={"Authorization": "Bearer access"},
    )

    assert resp.status_code == 422
