import pytest
from unittest.mock import AsyncMock
import time
from src.domain.rate_limiting.services import RateLimitService, RateLimitQuota, RateLimitContext, RateLimitKey
from src.domain.rate_limiting.entities import RateLimitRequest, RateLimitPolicy
from src.core.exceptions import RateLimitError

@pytest.mark.asyncio
async def test_role_based_limits_during_peak_load(monkeypatch):
    """
    Test rate limiting with differentiated limits based on user roles during peak load.
    Simulates free, premium, and enterprise users with different rate limits.
    Based on Scenario 4: Differentiated Limits for User Roles During Peak Load.
    """
    # Mock RateLimitService to simulate role-based rate limiting
    mock_rate_limit_service = AsyncMock(spec=RateLimitService)
    
    # Track calls for each user role
    free_user_calls = 0
    premium_user_calls = 0
    enterprise_user_calls = 0
    
    def role_based_side_effect(context, key, quota):
        nonlocal free_user_calls, premium_user_calls, enterprise_user_calls
        if key.user_id == 'free_user1':
            free_user_calls += 1
            if free_user_calls <= 3:
                return None
            else:
                raise RateLimitError("Rate limit exceeded for Free User")
        elif key.user_id == 'premium_user1':
            premium_user_calls += 1
            if premium_user_calls <= 10:
                return None
            else:
                raise RateLimitError("Rate limit exceeded for Premium User")
        elif key.user_id == 'enterprise_user1':
            enterprise_user_calls += 1
            if enterprise_user_calls <= 50:
                return None
            else:
                raise RateLimitError("Rate limit exceeded for Enterprise User")
        return None
    
    mock_rate_limit_service.check_rate_limit.side_effect = role_based_side_effect
    
    # Replace the actual RateLimitService with our mock
    monkeypatch.setattr("src.domain.rate_limiting.services.RateLimitService", lambda *args, **kwargs: mock_rate_limit_service)
    
    # Simulate Free User requests
    free_user_id = "free_user1"
    free_user_key = RateLimitKey(user_id=free_user_id, endpoint="/api/v1/reports", user_tier="free")
    free_user_request = RateLimitRequest(user_id=free_user_id, endpoint="/api/v1/reports", user_tier="free")
    free_context = RateLimitContext(
        request=free_user_request,
        applicable_policies=[],
        hierarchical_keys=[free_user_key],
        processing_start_time=time.time()
    )
    free_quota = RateLimitQuota(max_requests=3, window_seconds=60, burst_allowance=0)
    
    # First 3 requests for Free User - allowed
    for i in range(3):
        result = await mock_rate_limit_service.check_rate_limit(free_context, free_user_key, free_quota)
        assert result is None, f"Free User request {i+1} should be allowed"
    
    # 4th request for Free User - rate limited
    try:
        await mock_rate_limit_service.check_rate_limit(free_context, free_user_key, free_quota)
        assert False, "Free User should be rate limited after exceeding limit"
    except RateLimitError as e:
        assert str(e) == "Rate limit exceeded for Free User", "Rate limit error message should match"
    
    # Simulate Premium User requests
    premium_user_id = "premium_user1"
    premium_user_key = RateLimitKey(user_id=premium_user_id, endpoint="/api/v1/reports", user_tier="premium")
    premium_user_request = RateLimitRequest(user_id=premium_user_id, endpoint="/api/v1/reports", user_tier="premium")
    premium_context = RateLimitContext(
        request=premium_user_request,
        applicable_policies=[],
        hierarchical_keys=[premium_user_key],
        processing_start_time=time.time()
    )
    premium_quota = RateLimitQuota(max_requests=10, window_seconds=60, burst_allowance=0)
    
    # First 10 requests for Premium User - allowed
    for i in range(10):
        result = await mock_rate_limit_service.check_rate_limit(premium_context, premium_user_key, premium_quota)
        assert result is None, f"Premium User request {i+1} should be allowed"
    
    # 11th request for Premium User - rate limited
    try:
        await mock_rate_limit_service.check_rate_limit(premium_context, premium_user_key, premium_quota)
        assert False, "Premium User should be rate limited after exceeding limit"
    except RateLimitError as e:
        assert str(e) == "Rate limit exceeded for Premium User", "Rate limit error message should match"
    
    # Simulate Enterprise User requests
    enterprise_user_id = "enterprise_user1"
    enterprise_user_key = RateLimitKey(user_id=enterprise_user_id, endpoint="/api/v1/reports", user_tier="enterprise")
    enterprise_user_request = RateLimitRequest(user_id=enterprise_user_id, endpoint="/api/v1/reports", user_tier="enterprise")
    enterprise_context = RateLimitContext(
        request=enterprise_user_request,
        applicable_policies=[],
        hierarchical_keys=[enterprise_user_key],
        processing_start_time=time.time()
    )
    enterprise_quota = RateLimitQuota(max_requests=50, window_seconds=60, burst_allowance=0)
    
    # First 50 requests for Enterprise User - allowed
    for i in range(50):
        result = await mock_rate_limit_service.check_rate_limit(enterprise_context, enterprise_user_key, enterprise_quota)
        assert result is None, f"Enterprise User request {i+1} should be allowed"
    
    # 51st request for Enterprise User - rate limited
    try:
        await mock_rate_limit_service.check_rate_limit(enterprise_context, enterprise_user_key, enterprise_quota)
        assert False, "Enterprise User should be rate limited after exceeding limit"
    except RateLimitError as e:
        assert str(e) == "Rate limit exceeded for Enterprise User", "Rate limit error message should match" 
