from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from starlette.testclient import TestClient

from src.core.config.settings import settings
from src.core.dependencies.auth import get_current_user
from src.core.rate_limiting.ratelimiter import get_limiter
from src.domain.entities.user import Role, User
from src.main import app
from src.utils.i18n import get_translated_message, setup_i18n


@pytest.fixture(autouse=True)
def setup():
    """Setup i18n before each test."""
    setup_i18n()


@pytest.fixture
def client():
    """Provides a basic test client."""
    app.state.limiter = get_limiter()
    mock_admin_user = MagicMock(spec=User)
    mock_admin_user.role = Role.ADMIN
    mock_admin_user.is_active = True

    app.dependency_overrides[get_current_user] = lambda: mock_admin_user
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.mark.parametrize(
    "lang,expected_message",
    [
        ("en", "System is operational"),
        ("fa", "سیستم در حال کار است"),
        ("ar", "النظام يعمل"),
    ],
)
def test_health_check(client, lang, expected_message, monkeypatch):
    """Test health check endpoint with different languages."""
    monkeypatch.setattr(settings, "APP_ENV", "test")
    headers = {
        "Accept-Language": lang,
    }
    response = client.get("/api/v1/health", headers=headers)
    assert response.status_code == 200
    json_response = response.json()
    assert json_response["status"] == "ok"
    assert json_response["message"] == expected_message
    assert json_response["env"] == "test"
    assert "redis" in json_response["services"]
    assert "database" in json_response["services"]
    assert json_response["services"]["database"]["status"] == "healthy"


def test_health_check_default_language(client, monkeypatch):
    """Test health check endpoint with default language."""
    monkeypatch.setattr(settings, "APP_ENV", "test")
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    json_response = response.json()
    assert json_response["status"] == "ok"
    assert json_response["message"] == get_translated_message(
        "system_operational", settings.DEFAULT_LANGUAGE
    )
    assert json_response["env"] == "test"
    assert "redis" in json_response["services"]
    assert "database" in json_response["services"]
    assert json_response["services"]["database"]["status"] == "healthy"


def test_health_check_invalid_language(client, monkeypatch):
    """Test health check endpoint with invalid language falls back to default."""
    monkeypatch.setattr(settings, "APP_ENV", "test")
    headers = {
        "Accept-Language": "invalid",
    }
    response = client.get("/api/v1/health", headers=headers)
    assert response.status_code == 200
    json_response = response.json()
    assert json_response["status"] == "ok"
    assert json_response["message"] == get_translated_message(
        "system_operational", settings.DEFAULT_LANGUAGE
    )
    assert json_response["env"] == "test"
    assert "redis" in json_response["services"]
    assert "database" in json_response["services"]
    assert json_response["services"]["database"]["status"] == "healthy"
