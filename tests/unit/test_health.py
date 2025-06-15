from httpx import AsyncClient
from main import app
from utils.i18n import setup_i18n
from core.logging import logger
from core.config.settings import settings
import pytest
from starlette.testclient import TestClient

@pytest.fixture(autouse=True)
def setup_i18n_for_tests():
    logger.debug("setting_up_i18n_for_tests")
    setup_i18n()

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

@pytest.mark.parametrize("lang,expected_message", [
    ("en", "System is operational"),
    ("fa", "سیستم عملیاتی است"),
    ("ar", "النظام يعمل"),
])
def test_health_check(client, lang, expected_message, monkeypatch):
    monkeypatch.setattr(settings, 'APP_ENV', 'test')
    response = client.get("/api/v1/health", headers={"Accept-Language": lang})
    assert response.status_code == 200
    json_response = response.json()
    assert json_response["status"] == "ok"
    assert json_response["env"] == "test"
    assert json_response["message"] == expected_message

def test_health_check_default_language(client, monkeypatch):
    monkeypatch.setattr(settings, 'APP_ENV', 'test')
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    json_response = response.json()
    assert json_response["status"] == "ok"
    assert json_response["env"] == "test"
    assert json_response["message"] == "System is operational"