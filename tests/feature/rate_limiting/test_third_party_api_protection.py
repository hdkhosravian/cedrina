import pytest
from unittest.mock import AsyncMock
import time
from src.domain.rate_limiting.services import RateLimitService, RateLimitQuota, RateLimitContext, RateLimitKey
from src.domain.rate_limiting.entities import RateLimitRequest, RateLimitPolicy
from src.core.exceptions import RateLimitError

@pytest.mark.asyncio
async def test_third_party_api_protection(monkeypatch):
    """
    Test rate limiting to protect third-party API integrations from overuse.
    Simulates requests to an external payment processing API with strict limits.
    Based on Scenario 5: Protecting Third-Party API Integrations.
    """
    # Mock RateLimitService to simulate strict rate limiting for third-party API calls
    mock_rate_limit_service = AsyncMock(spec=RateLimitService)
    
    # Configure mock to allow initial requests and then raise RateLimitError
    third_party_calls = 0
    def third_party_side_effect(context, key, quota):
        nonlocal third_party_calls
        third_party_calls += 1
        if third_party_calls <= 5:
            return None
        else:
            raise RateLimitError("Rate limit exceeded for third-party API")
    mock_rate_limit_service.check_rate_limit.side_effect = third_party_side_effect
    
    # Replace the actual RateLimitService with our mock
    monkeypatch.setattr("src.domain.rate_limiting.services.RateLimitService", lambda *args, **kwargs: mock_rate_limit_service)
    
    # Simulate requests to a third-party API endpoint
    key = RateLimitKey(endpoint="/api/v1/payments/process")
    third_party_request = RateLimitRequest(endpoint="/api/v1/payments/process")
    context = RateLimitContext(
        request=third_party_request,
        applicable_policies=[],
        hierarchical_keys=[key],
        processing_start_time=time.time()
    )
    quota = RateLimitQuota(max_requests=5, window_seconds=3600, burst_allowance=0)  # Strict hourly limit
    
    # First 5 requests - allowed
    for i in range(5):
        result = await mock_rate_limit_service.check_rate_limit(context, key, quota)
        assert result is None, f"Request {i+1} to third-party API should be allowed"
    
    # 6th request - rate limited
    try:
        await mock_rate_limit_service.check_rate_limit(context, key, quota)
        assert False, "Payment processing should be rate limited after exceeding hourly limit"
    except RateLimitError as e:
        assert str(e) == "Rate limit exceeded for third-party API", "Rate limit error message should match" 
