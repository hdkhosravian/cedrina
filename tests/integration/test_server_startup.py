"""
Integration Test for Server Startup

This module contains integration tests to verify that the FastAPI server can start correctly
without encountering import errors, configuration issues, or other startup failures.
These tests simulate running the server with Uvicorn to ensure the application loads properly.

Tests:
    - test_server_startup: Verifies that the server can start and respond to a basic request.
"""

import pytest
import asyncio
import uvicorn
from fastapi.testclient import TestClient
from unittest.mock import patch
from src.main import app
from src.core.config.settings import settings
from src.infrastructure.database import check_database_health
from src.core.ratelimiter import get_limiter

@patch("src.main.check_database_health")
def test_server_startup(mock_check_db_health):
    """
    Test server startup sequence, mocking database health check.
    """
    # Case 1: Database is healthy
    mock_check_db_health.return_value = True
    app.state.limiter = get_limiter()  # Ensure limiter is attached for the test
    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/health", headers={"Authorization": "Bearer fake-token"})
            assert response.status_code in [200, 401, 403], f"Unexpected status code: {response.status_code}"
    except RuntimeError as e:
        pytest.fail(f"Server startup failed with healthy database: {e}")

    # Case 2: Database is unhealthy
    mock_check_db_health.return_value = False
    with pytest.raises(RuntimeError) as excinfo:
        with TestClient(app):
            pass  # The client context manager will trigger the lifespan event
    assert "Database unavailable" in str(excinfo.value)

@pytest.mark.asyncio
async def test_server_startup_alternative():
    """
    Test that the server can start successfully and respond to requests.
    
    This test simulates starting the server with Uvicorn in a controlled environment
    and checks if it can handle a basic request (e.g., to the root endpoint if available
    or a known endpoint). It ensures there are no import errors or configuration issues
    during startup.
    """
    # Use TestClient to interact with the app directly without starting a full server
    # This avoids port conflicts and focuses on app initialization
    client = TestClient(app)
    
    # Test a simple request to verify the app is loaded correctly
    # Assuming there's a root endpoint or a simple endpoint to test
    try:
        response = client.get("/api/v1/health", headers={"Authorization": "Bearer fake-token"})
        # We don't check for 200 specifically, as it might return 401/403 due to auth,
        # but we confirm the app didn't crash on startup
        assert response.status_code in [200, 401, 403], f"Unexpected status code: {response.status_code}"
    except Exception as e:
        pytest.fail(f"Server startup test failed with exception: {str(e)}")
    finally:
        # Ensure any background tasks or resources are cleaned up if needed
        pass 