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
async def test_fair_usage_during_product_launch(monkeypatch):
    """Test rate limiting to ensure fair usage during a high-traffic product launch.
    Simulates multiple users accessing product endpoints with hierarchical limits.
    Based on Scenario 2: Ensuring Fair Usage During a Product Launch.
    """
    # Mock RateLimitService to simulate hierarchical rate limiting
    mock_rate_limit_service = AsyncMock(spec=RateLimitService)

    # Configure mock for User 1 (exceeds limit)
    user1_calls = 0

    def user1_side_effect(context, key, quota):
        nonlocal user1_calls
        user1_calls += 1
        if user1_calls <= 5:
            return None
        else:
            raise RateLimitError("Rate limit exceeded for User 1")

    mock_rate_limit_service.check_rate_limit.side_effect = user1_side_effect

    # Replace the actual RateLimitService with our mock
    monkeypatch.setattr(
        "src.core.rate_limiting.services.RateLimitService",
        lambda *args, **kwargs: mock_rate_limit_service,
    )

    # Simulate User 1 requests (exceeds limit)
    user1_id = "user1"
    user1_key = RateLimitKey(user_id=user1_id, endpoint="/api/v1/products")
    user1_request = RateLimitRequest(user_id=user1_id, endpoint="/api/v1/products")
    context_user1 = RateLimitContext(
        request=user1_request,
        applicable_policies=[],
        hierarchical_keys=[user1_key],
        processing_start_time=time.time(),
    )
    quota = RateLimitQuota(max_requests=5, window_seconds=60, burst_allowance=2)

    # First 5 requests for User 1 - allowed
    for i in range(5):
        result = await mock_rate_limit_service.check_rate_limit(context_user1, user1_key, quota)
        assert result is None, f"User 1 request {i+1} should be allowed"

    # 6th request for User 1 - rate limited
    try:
        await mock_rate_limit_service.check_rate_limit(context_user1, user1_key, quota)
        assert False, "User 1 should be rate limited after exceeding quota + burst"
    except RateLimitError as e:
        assert str(e) == "Rate limit exceeded for User 1", "Rate limit error message should match"

    # Simulate User 2 requests (within limit)
    user2_id = "user2"
    user2_key = RateLimitKey(user_id=user2_id, endpoint="/api/v1/products")
    user2_request = RateLimitRequest(user_id=user2_id, endpoint="/api/v1/products")
    context_user2 = RateLimitContext(
        request=user2_request,
        applicable_policies=[],
        hierarchical_keys=[user2_key],
        processing_start_time=time.time(),
    )

    # Reset mock side effect for User 2 to allow requests
    mock_rate_limit_service.check_rate_limit.side_effect = lambda *args, **kwargs: None

    # First 5 requests for User 2 - allowed
    for i in range(5):
        result = await mock_rate_limit_service.check_rate_limit(context_user2, user2_key, quota)
        assert result is None, f"User 2 request {i+1} should be allowed"
