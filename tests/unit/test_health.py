from httpx import AsyncClient
from src.main import app
from src.utils.i18n import setup_i18n
from src.core.logging import logger
from src.core.config.settings import settings
import pytest
from starlette.testclient import TestClient
from fastapi.testclient import TestClient
from unittest.mock import MagicMock
from src.core.dependencies.auth import get_current_user
from src.domain.entities.user import User, Role

@pytest.fixture(autouse=True)
def setup_i18n_for_tests():
    logger.debug("setting_up_i18n_for_tests")
    setup_i18n()

@pytest.fixture
def client():
    """Provides a test client with a mock admin user."""
    mock_admin_user = MagicMock(spec=User)
    mock_admin_user.role = Role.ADMIN
    mock_admin_user.is_active = True
    
    app.dependency_overrides[get_current_user] = lambda: mock_admin_user
    yield TestClient(app)
    app.dependency_overrides.clear()

@pytest.mark.parametrize("lang,expected_message", [
    ("en", "System is operational"),
    ("fa", "سیستم عملیاتی است"),
    ("ar", "النظام يعمل"),
])
def test_health_check(client, lang, expected_message, monkeypatch):
    monkeypatch.setattr(settings, 'APP_ENV', 'test')
    headers = {
        "Accept-Language": lang,
    }
    response = client.get("/api/v1/health", headers=headers)
    assert response.status_code == 200
    json_response = response.json()
    assert json_response["status"] == "ok"
    assert json_response["message"] == expected_message
    assert json_response["env"] == "test"
    assert "database" in json_response["services"]
    assert json_response["services"]["database"]["status"] == "healthy"

def test_health_check_default_language(client, monkeypatch):
    monkeypatch.setattr(settings, 'APP_ENV', 'test')
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    json_response = response.json()
    assert json_response["status"] == "ok"
    assert json_response["message"] == "System is operational"
    assert json_response["env"] == "test"
    assert "database" in json_response["services"]
    assert json_response["services"]["database"]["status"] == "healthy"