import os
import sys
from unittest.mock import Mock

import pytest

# Adjust sys.path to include src directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../src")))

from core.metrics import MetricsCollector, record_metric


@pytest.fixture
def collector():
    """Fixture to create a fresh MetricsCollector instance for each test."""
    collector = MetricsCollector()
    return collector


def test_collect_system_metrics(collector, mocker):
    """Test collecting system metrics with mocked psutil values."""
    # Mock psutil functions
    mocker.patch("psutil.cpu_percent", return_value=50.0)
    mocker.patch(
        "psutil.virtual_memory", return_value=Mock(percent=30.0, used=3000000000, total=10000000000)
    )
    mocker.patch(
        "psutil.disk_usage", return_value=Mock(percent=40.0, used=40000000000, total=100000000000)
    )

    metrics = collector.collect_system_metrics()
    assert metrics["cpu_percent"] == 50.0
    assert metrics["memory_percent"] == 30.0
    assert metrics["memory_used"] == 3000000000
    assert metrics["memory_total"] == 10000000000
    assert metrics["disk_percent"] == 40.0
    assert metrics["disk_used"] == 40000000000
    assert metrics["disk_total"] == 100000000000
    assert "uptime" in metrics
    assert metrics["uptime"] > 0


def test_collect_system_metrics_error(collector, mocker):
    """Test collecting system metrics when an error occurs."""
    mocker.patch("psutil.cpu_percent", side_effect=Exception("Test error"))
    metrics = collector.collect_system_metrics()
    assert metrics == {}


def test_record_request_metric(collector):
    """Test recording HTTP request metrics."""
    collector.record_request_metric("/api/test", "GET", 200, 0.123)
    requests = collector.get_metrics()["application"]["requests"]
    assert "GET:/api/test" in requests
    assert requests["GET:/api/test"]["count"] == 1
    assert requests["GET:/api/test"]["total_duration"] == 0.123
    assert requests["GET:/api/test"]["status_codes"]["200"] == 1


def test_record_database_metric_success(collector):
    """Test recording successful database operation metrics."""
    collector.record_database_metric("select_user", 0.05, True)
    ops = collector.get_metrics()["database"]["operations"]
    assert "select_user" in ops
    assert ops["select_user"]["count"] == 1
    assert ops["select_user"]["total_duration"] == 0.05
    assert ops["select_user"]["success_count"] == 1
    assert ops["select_user"]["error_count"] == 0


def test_record_database_metric_failure(collector):
    """Test recording failed database operation metrics."""
    collector.record_database_metric("insert_user", 0.1, False)
    ops = collector.get_metrics()["database"]["operations"]
    assert "insert_user" in ops
    assert ops["insert_user"]["count"] == 1
    assert ops["insert_user"]["total_duration"] == 0.1
    assert ops["insert_user"]["success_count"] == 0
    assert ops["insert_user"]["error_count"] == 1


def test_record_cache_metric_hit(collector):
    """Test recording cache hit metrics."""
    collector.record_cache_metric("get_user", True)
    ops = collector.get_metrics()["cache"]["operations"]
    assert "get_user" in ops
    assert ops["get_user"]["hits"] == 1
    assert ops["get_user"]["misses"] == 0


def test_record_cache_metric_miss(collector):
    """Test recording cache miss metrics."""
    collector.record_cache_metric("get_user", False)
    ops = collector.get_metrics()["cache"]["operations"]
    assert "get_user" in ops
    assert ops["get_user"]["hits"] == 0
    assert ops["get_user"]["misses"] == 1


def test_get_metrics_updates_system_metrics(collector, mocker):
    """Test that get_metrics updates system metrics."""
    mocker.patch("psutil.cpu_percent", return_value=75.0)
    mocker.patch(
        "psutil.virtual_memory", return_value=Mock(percent=25.0, used=2500000000, total=10000000000)
    )
    mocker.patch(
        "psutil.disk_usage", return_value=Mock(percent=35.0, used=35000000000, total=100000000000)
    )

    metrics = collector.get_metrics()
    assert metrics["system"]["cpu_percent"] == 75.0
    assert metrics["system"]["memory_percent"] == 25.0
    assert metrics["system"]["disk_percent"] == 35.0


def test_reset_metrics(collector, mocker):
    """Test resetting all metrics to initial state."""
    collector.record_request_metric("/api/test", "GET", 200, 0.123)
    collector.record_database_metric("select_user", 0.05, True)
    collector.record_cache_metric("get_user", True)

    collector.reset_metrics()
    # Mock collect_system_metrics to prevent repopulation of system metrics during get_metrics()
    mocker.patch.object(collector, "collect_system_metrics", return_value={})
    metrics = collector.get_metrics()
    assert metrics["application"] == {}
    assert metrics["database"] == {}
    assert metrics["cache"] == {}
    assert metrics["system"] == {}


@pytest.mark.asyncio
async def test_record_metric_decorator_database_success(mocker):
    """Test record_metric decorator for database operations with success."""
    collector = MetricsCollector()
    mocker.patch("core.metrics.metrics_collector", collector)

    @record_metric("database")
    async def test_db_func():
        return "success"

    result = await test_db_func()
    assert result == "success"
    ops = collector.get_metrics()["database"]["operations"]
    assert "test_db_func" in ops
    assert ops["test_db_func"]["count"] == 1
    assert ops["test_db_func"]["success_count"] == 1
    assert ops["test_db_func"]["error_count"] == 0


@pytest.mark.asyncio
async def test_record_metric_decorator_database_failure(mocker):
    """Test record_metric decorator for database operations with failure."""
    collector = MetricsCollector()
    mocker.patch("core.metrics.metrics_collector", collector)

    @record_metric("database")
    async def test_db_func():
        raise ValueError("failure")

    with pytest.raises(ValueError, match="failure"):
        await test_db_func()
    ops = collector.get_metrics()["database"]["operations"]
    assert "test_db_func" in ops
    assert ops["test_db_func"]["count"] == 1
    assert ops["test_db_func"]["success_count"] == 0
    assert ops["test_db_func"]["error_count"] == 1


@pytest.mark.asyncio
async def test_record_metric_decorator_cache(mocker):
    """Test record_metric decorator for cache operations."""
    collector = MetricsCollector()
    mocker.patch("core.metrics.metrics_collector", collector)

    @record_metric("cache")
    async def test_cache_func():
        return "hit"

    result = await test_cache_func()
    assert result == "hit"
    ops = collector.get_metrics()["cache"]["operations"]
    assert "test_cache_func" in ops
    assert ops["test_cache_func"]["hits"] == 1
    assert ops["test_cache_func"]["misses"] == 0


def test_record_metric_decorator_sync_database_success(mocker):
    """Test record_metric decorator for synchronous database operations with success."""
    collector = MetricsCollector()
    mocker.patch("core.metrics.metrics_collector", collector)

    @record_metric("database")
    def test_db_func():
        return "success"

    result = test_db_func()
    assert result == "success"
    ops = collector.get_metrics()["database"]["operations"]
    assert "test_db_func" in ops
    assert ops["test_db_func"]["count"] == 1
    assert ops["test_db_func"]["success_count"] == 1
    assert ops["test_db_func"]["error_count"] == 0
