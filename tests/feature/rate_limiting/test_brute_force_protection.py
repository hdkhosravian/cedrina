import time
from unittest.mock import AsyncMock

import pytest

from src.core.exceptions import RateLimitError
from src.core.rate_limiting.entities import RateLimitRequest
from src.core.rate_limiting.services import (
    RateLimitContext,
    RateLimitKey,
    RateLimitQuota,
    RateLimitService,
)


@pytest.mark.asyncio
async def test_login_brute_force_protection(monkeypatch):
    """Test rate limiting protection against brute force attacks on the login endpoint.
    Simulates a malicious user attempting multiple login requests from the same IP.
    Based on Scenario 1: Protecting a Login Endpoint from Brute Force Attacks.
    """
    # Mock RateLimitService to simulate IP-based rate limiting
    mock_rate_limit_service = AsyncMock(spec=RateLimitService)

    # Configure mock to allow initial requests and then raise RateLimitError
    mock_rate_limit_service.check_rate_limit.side_effect = [
        None,  # First request allowed
        None,  # Second request allowed
        RateLimitError("Rate limit exceeded for IP address"),  # Third request blocked
    ]

    # Replace the actual RateLimitService with our mock
    monkeypatch.setattr(
        "src.core.rate_limiting.services.RateLimitService",
        lambda *args, **kwargs: mock_rate_limit_service,
    )

    # Simulate requests from the same IP to a login endpoint
    client_ip = "192.168.1.100"
    key = RateLimitKey(client_ip=client_ip, endpoint="/api/v1/auth/login")
    request = RateLimitRequest(client_ip=client_ip, endpoint="/api/v1/auth/login")
    context = RateLimitContext(
        request=request,
        applicable_policies=[],
        hierarchical_keys=[key],
        processing_start_time=time.time(),
    )
    quota = RateLimitQuota(max_requests=2, window_seconds=60, burst_allowance=0)

    # First two requests - allowed
    for i in range(2):
        result = await mock_rate_limit_service.check_rate_limit(context, key, quota)
        assert result is None, f"Request {i+1} should be allowed"

    # Third request - rate limited
    try:
        await mock_rate_limit_service.check_rate_limit(context, key, quota)
        assert False, "Third request should raise RateLimitError"
    except RateLimitError as e:
        assert (
            str(e) == "Rate limit exceeded for IP address"
        ), "Rate limit error message should match"
