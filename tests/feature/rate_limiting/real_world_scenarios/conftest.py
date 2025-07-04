"""Real-world scenario test configuration.

This module provides fixtures and utilities for comprehensive end-to-end testing
of rate limiting in real-world user scenarios, including complete authentication
flows, different user tiers, and various API interactions.
"""

import time
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from src.core.rate_limiting.entities import RateLimitPolicy, RateLimitQuota
from src.core.rate_limiting.services import AdvancedRateLimiter
from src.core.rate_limiting.value_objects import RateLimitAlgorithm


class ScenarioClient:
    """Enhanced test client for real-world scenario testing."""

    def __init__(self, client: TestClient):
        self.client = client
        self.headers: Dict[str, str] = {}
        self.user_data: Optional[Dict[str, Any]] = None

    def set_auth_headers(self, token: str, user_type: str = "regular"):
        """Set authentication headers for requests."""
        self.headers = {"Authorization": f"Bearer {token}_{user_type}"}

    def clear_auth(self):
        """Clear authentication headers."""
        self.headers = {}

    def post(self, url: str, **kwargs):
        """POST request with authentication headers."""
        kwargs.setdefault("headers", {}).update(self.headers)
        return self.client.post(url, **kwargs)

    def get(self, url: str, **kwargs):
        """GET request with authentication headers."""
        kwargs.setdefault("headers", {}).update(self.headers)
        return self.client.get(url, **kwargs)

    def put(self, url: str, **kwargs):
        """PUT request with authentication headers."""
        kwargs.setdefault("headers", {}).update(self.headers)
        return self.client.put(url, **kwargs)

    def delete(self, url: str, **kwargs):
        """DELETE request with authentication headers."""
        kwargs.setdefault("headers", {}).update(self.headers)
        return self.client.delete(url, **kwargs)


@pytest.fixture(scope="function")
def scenario_client(client):
    """Enhanced client for scenario testing."""
    return ScenarioClient(client)


@pytest.fixture(scope="function")
def mock_rate_limiter():
    """Mock rate limiter with configurable policies."""
    limiter = AsyncMock(spec=AdvancedRateLimiter)

    # Default: Allow all requests
    limiter.check_rate_limit.return_value = {
        "allowed": True,
        "limit": 100,
        "remaining": 99,
        "reset_time": int(time.time()) + 3600,
        "retry_after": None,
    }

    return limiter


@pytest.fixture(scope="function")
def rate_limit_policies():
    """Standard rate limiting policies for different scenarios."""
    return {
        "free_tier": RateLimitPolicy(
            name="free_tier",
            quotas=[
                RateLimitQuota(max_requests=10, window_seconds=60),  # 10/minute
                RateLimitQuota(max_requests=100, window_seconds=3600),  # 100/hour
            ],
            algorithm=RateLimitAlgorithm.FIXED_WINDOW,
        ),
        "premium_tier": RateLimitPolicy(
            name="premium_tier",
            quotas=[
                RateLimitQuota(max_requests=100, window_seconds=60),  # 100/minute
                RateLimitQuota(max_requests=1000, window_seconds=3600),  # 1000/hour
            ],
            algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
        ),
        "api_tier": RateLimitPolicy(
            name="api_tier",
            quotas=[
                RateLimitQuota(max_requests=1000, window_seconds=60),  # 1000/minute
                RateLimitQuota(max_requests=10000, window_seconds=3600),  # 10000/hour
            ],
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
        ),
        "login_protection": RateLimitPolicy(
            name="login_protection",
            quotas=[RateLimitQuota(max_requests=5, window_seconds=300)],  # 5 attempts per 5 minutes
            algorithm=RateLimitAlgorithm.FIXED_WINDOW,
        ),
        "registration_protection": RateLimitPolicy(
            name="registration_protection",
            quotas=[
                RateLimitQuota(max_requests=3, window_seconds=600)  # 3 registrations per 10 minutes
            ],
            algorithm=RateLimitAlgorithm.FIXED_WINDOW,
        ),
    }


@pytest.fixture(scope="function")
def user_scenarios():
    """Different user scenarios for testing."""
    return {
        "new_user": {
            "username": "new_user_123",
            "email": "newuser123@example.com",
            "password": "SecurePassword123!",
            "tier": "free",
        },
        "premium_user": {
            "username": "premium_user_456",
            "email": "premium456@example.com",
            "password": "PremiumPassword456!",
            "tier": "premium",
        },
        "api_user": {
            "username": "api_user_789",
            "email": "apiuser789@example.com",
            "password": "ApiPassword789!",
            "tier": "api",
        },
        "existing_user": {
            "username": "existing_user",
            "email": "existing@example.com",
            "password": "ExistingPassword123!",
            "tier": "free",
        },
    }


@pytest.fixture(scope="function")
def api_endpoints():
    """API endpoints for testing different scenarios."""
    return {
        "auth": {
            "register": "/api/v1/auth/register",
            "login": "/api/v1/auth/login",
            "refresh": "/api/v1/auth/refresh",
        },
        "protected": {
            "profile": "/api/v1/user/profile",
            "settings": "/api/v1/user/settings",
            "data": "/api/v1/user/data",
        },
        "api": {
            "search": "/api/v1/search",
            "analytics": "/api/v1/analytics",
            "export": "/api/v1/export",
        },
        "admin": {
            "policies": "/api/v1/admin/policies",
            "users": "/api/v1/admin/users",
            "metrics": "/api/v1/admin/metrics",
        },
    }


class ScenarioState:
    """Maintains state throughout a scenario test."""

    def __init__(self):
        self.users: Dict[str, Dict[str, Any]] = {}
        self.tokens: Dict[str, str] = {}
        self.request_counts: Dict[str, int] = {}
        self.rate_limit_hits: List[Dict[str, Any]] = []

    def register_user(self, user_type: str, user_data: Dict[str, Any], token: str):
        """Register a user for the scenario."""
        self.users[user_type] = user_data
        self.tokens[user_type] = token
        self.request_counts[user_type] = 0

    def record_request(self, user_type: str, endpoint: str, response_code: int):
        """Record a request for analytics."""
        if user_type not in self.request_counts:
            self.request_counts[user_type] = 0
        self.request_counts[user_type] += 1
        if response_code == 429:  # Rate limited
            self.rate_limit_hits.append(
                {
                    "user_type": user_type,
                    "endpoint": endpoint,
                    "timestamp": time.time(),
                    "request_count": self.request_counts[user_type],
                }
            )

    def get_user_token(self, user_type: str) -> str:
        """Get authentication token for user type."""
        return self.tokens.get(user_type, "")

    def get_rate_limit_summary(self) -> Dict[str, Any]:
        """Get summary of rate limiting activity."""
        return {
            "total_requests": sum(self.request_counts.values()),
            "rate_limit_hits": len(self.rate_limit_hits),
            "users_affected": len(set(hit["user_type"] for hit in self.rate_limit_hits)),
            "endpoints_affected": len(set(hit["endpoint"] for hit in self.rate_limit_hits)),
        }


@pytest.fixture(scope="function")
def scenario_state():
    """Scenario state tracker."""
    return ScenarioState()


@pytest.fixture(scope="function")
def mock_redis():
    """Mock Redis client for rate limiting tests."""
    redis_mock = AsyncMock()

    # Mock Redis operations
    redis_mock.get.return_value = None
    redis_mock.set.return_value = True
    redis_mock.incr.return_value = 1
    redis_mock.expire.return_value = True
    redis_mock.ttl.return_value = 3600
    redis_mock.delete.return_value = True
    redis_mock.pipeline.return_value = redis_mock
    redis_mock.execute.return_value = [1, True]

    return redis_mock


def wait_for_rate_limit_reset(seconds: int = 1):
    """Utility to wait for rate limit windows to reset."""
    time.sleep(seconds)


def simulate_burst_requests(
    client: ScenarioClient, endpoint: str, count: int, data: Optional[Dict] = None
) -> List[int]:
    """Simulate burst requests and return response status codes."""
    responses = []
    for i in range(count):
        if data:
            response = client.post(endpoint, json=data)
        else:
            response = client.get(endpoint)
        responses.append(response.status_code)

        # Small delay to avoid overwhelming the test system
        time.sleep(0.01)

    return responses


def assert_rate_limit_response(response, expected_retry_after: Optional[int] = None):
    """Assert that a response indicates rate limiting."""
    assert response.status_code == 429
    assert "X-RateLimit-Limit" in response.headers
    assert "X-RateLimit-Remaining" in response.headers
    assert "X-RateLimit-Reset" in response.headers

    if expected_retry_after:
        assert "Retry-After" in response.headers
        assert int(response.headers["Retry-After"]) >= expected_retry_after


def assert_successful_response(response, expected_status: int = 200):
    """Assert that a response is successful."""
    assert response.status_code == expected_status
    if hasattr(response, "json"):
        data = response.json()
        assert data is not None
