"""
Tests for the metrics endpoint.
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock

from src.main import app
from src.core.metrics import metrics_collector
from src.core.config.settings import settings
from src.core.dependencies.auth import get_current_user
from src.domain.entities.user import User, Role

@pytest.fixture
def client():
    """Provides a test client with a mock admin user."""
    mock_admin_user = MagicMock(spec=User)
    mock_admin_user.role = Role.ADMIN
    mock_admin_user.is_active = True
    
    app.dependency_overrides[get_current_user] = lambda: mock_admin_user
    yield TestClient(app)
    app.dependency_overrides.clear()

def test_metrics_endpoint_requires_debug_mode(client):
    """Test that metrics endpoint requires debug mode."""
    settings.DEBUG = False
    response = client.get("/api/v1/metrics")
    assert response.status_code == 403 # Should be forbidden when debug is off

def test_metrics_endpoint_returns_metrics(client):
    """Test that metrics endpoint returns metrics."""
    settings.DEBUG = True

    metrics_collector.reset_metrics()
    metrics_collector.record_request_metric("/test", "GET", 200, 0.1)
    
    response = client.get("/api/v1/metrics")
    assert response.status_code == 200
    response_json = response.json()
    assert "application" in response_json["metrics"]
    assert "requests" in response_json["metrics"]["application"]

def test_metrics_collector_reset(client):
    """Test that metrics collector reset works."""
    # Record some metrics
    metrics_collector.record_request_metric("/test", "GET", 200, 0.1)
    
    # Reset metrics
    metrics_collector.reset_metrics()
    
    # Verify metrics are reset
    metrics = metrics_collector.get_metrics()
    assert "requests" not in metrics["application"] 