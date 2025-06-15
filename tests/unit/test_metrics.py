"""
Tests for the metrics endpoint.
"""
import pytest
from fastapi.testclient import TestClient
from main import app
from core.metrics import metrics_collector
from core.config.settings import settings

@pytest.fixture(autouse=True)
def setup_test_environment():
    """Setup test environment."""
    settings.DEBUG = True
    metrics_collector.reset_metrics()
    yield
    settings.DEBUG = False

def test_metrics_endpoint_requires_debug_mode():
    """Test that metrics endpoint requires debug mode."""
    settings.DEBUG = False
    with TestClient(app) as client:
        response = client.get("/api/v1/metrics")
        assert response.status_code == 403
        assert response.json()["detail"] == "Metrics endpoint is only available in debug mode"

def test_metrics_endpoint_returns_metrics():
    """Test that metrics endpoint returns metrics."""
    settings.DEBUG = True
    
    # Record some test metrics
    metrics_collector.record_request_metric("/test", "GET", 200, 0.1)
    metrics_collector.record_database_metric("test_query", 0.2, True)
    metrics_collector.record_cache_metric("test_cache", True)
    
    with TestClient(app) as client:
        response = client.get("/api/v1/metrics")
        assert response.status_code == 200
        
        data = response.json()
        assert "timestamp" in data
        assert "metrics" in data
        
        metrics = data["metrics"]
        assert "system" in metrics
        assert "application" in metrics
        assert "database" in metrics
        assert "cache" in metrics
        
        # Verify recorded metrics
        assert metrics["application"]["requests"]["GET:/test"]["count"] == 1
        assert metrics["database"]["operations"]["test_query"]["success_count"] == 1
        assert metrics["cache"]["operations"]["test_cache"]["hits"] == 1

def test_metrics_collector_reset():
    """Test that metrics collector reset works."""
    # Record some metrics
    metrics_collector.record_request_metric("/test", "GET", 200, 0.1)
    
    # Reset metrics
    metrics_collector.reset_metrics()
    
    # Verify metrics are reset
    metrics = metrics_collector.get_metrics()
    assert "requests" not in metrics["application"] 