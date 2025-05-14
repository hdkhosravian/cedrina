import pytest
from fastapi.testclient import TestClient
from src.main import app
from src.utils.i18n import setup_i18n
from src.core.logging import logger

@pytest.fixture(autouse=True)
def setup_i18n_for_tests():
    logger.debug("setting_up_i18n_for_tests")
    setup_i18n()

@pytest.fixture
def client():
    return TestClient(app)

@pytest.mark.parametrize("lang,expected_message", [
    ("en", "System is operational"),
    ("fa", "سیستم عملیاتی است"),
    ("ar", "النظام يعمل"),
])
def test_health_check(client, lang, expected_message):
    response = client.get("/api/v1/health", headers={"Accept-Language": lang})
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "env": "test", "message": expected_message}