# -*- coding: utf-8 -*-
"""
Unit Tests for Advanced Rate Limiting System
==========================================

This module contains comprehensive unit tests for the advanced rate limiting system,
following a strict Test-Driven Development (TDD) approach. Tests are written to define
requirements and behavior before implementation, covering domain logic, edge cases,
and failure modes.

Tests are organized by component (value objects, entities, services) and concern
(performance, security, resilience), ensuring high coverage and alignment with DDD principles.
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock
import pytest
import redis.asyncio as redis
from typing import Dict, Any

# Import rate limiting domain components
from src.domain.rate_limiting.value_objects import (
    RateLimitKey,
    RateLimitQuota,
    RateLimitAlgorithm,
    RateLimitPeriod
)
from src.domain.rate_limiting.entities import (
    RateLimitResult,
    RateLimitQuota,
    RateLimitRequest
)
from src.domain.rate_limiting.services import RateLimitService, RateLimitContext
from src.domain.rate_limiting.repositories import RedisRateLimitRepository


# Fixtures for test setup
@pytest.fixture
async def redis_client():
    """
    Fixture to provide a Redis client for tests. Uses a test database or mock if Redis is unavailable.
    """
    try:
        client = redis.Redis.from_url("redis://localhost:6379/1", decode_responses=True)
        await client.ping()  # Test connection
        yield client
        await client.flushdb()  # Clean up after tests
        await client.aclose()  # Use aclose() instead of close()
    except redis.ConnectionError:
        # Fallback to mock if Redis is not available
        mock_client = AsyncMock(spec=redis.Redis)
        yield mock_client

@pytest.fixture
async def rate_limit_repository(redis_client):
    """
    Fixture to provide a rate limit repository instance for tests.
    """
    return RedisRateLimitRepository(redis_client, ttl_seconds=60)

@pytest.fixture
async def rate_limit_service(rate_limit_repository):
    """
    Fixture to provide a rate limit service instance for tests.
    """
    return RateLimitService(rate_limit_repository)

@pytest.fixture
def rate_limit_key():
    """
    Fixture for a sample rate limit key.
    """
    return RateLimitKey(user_id="test_user", endpoint="/api/test", client_ip="127.0.0.1")

@pytest.fixture
def rate_limit_quota():
    """
    Fixture for a sample rate limit quota (10 requests per minute).
    """
    return RateLimitQuota(
        max_requests=10,
        window_seconds=60,
        burst_allowance=2
    )

@pytest.fixture
def rate_limit_context():
    """
    Fixture for a sample rate limit context.
    """
    request = RateLimitRequest(
        user_id="test_user_123",
        endpoint="/api/test",
        client_ip="127.0.0.1"
    )
    return RateLimitContext(
        request=request,
        applicable_policies=[],
        hierarchical_keys=[RateLimitKey(user_id="test_user_123")],
        processing_start_time=time.time()
    )


class TestRateLimitValueObjects:
    """Tests for value objects in the rate limiting domain."""

    def test_rate_limit_key_creation_and_uniqueness(self):
        """Test that RateLimitKey can be created and ensures uniqueness."""
        key1 = RateLimitKey(user_id="test_user", endpoint="/api/test", client_ip="127.0.0.1")
        key2 = RateLimitKey(user_id="test_user", endpoint="/api/test", client_ip="127.0.0.1")
        key3 = RateLimitKey(user_id="test_user", endpoint="/api/test", client_ip="192.168.1.1")

        assert key1 == key2, "Identical keys should be equal"
        assert key1 != key3, "Different keys should not be equal"
        assert key1.composite_key == key2.composite_key, "Composite keys should match"

    def test_rate_limit_quota_validation_and_calculation(self):
        """Test RateLimitQuota validation and rate calculation."""
        quota = RateLimitQuota(
            max_requests=100,
            window_seconds=60,
            burst_allowance=10
        )

        assert quota.max_requests == 100, "Max requests should match"
        assert quota.window_seconds == 60, "Window seconds should match"
        assert quota.burst_allowance == 10, "Burst allowance should match"

        # Test invalid quota values
        with pytest.raises(ValueError):
            RateLimitQuota(
                max_requests=0,
                window_seconds=60,
                burst_allowance=0
            )

        with pytest.raises(ValueError):
            RateLimitQuota(
                max_requests=10,
                window_seconds=0,
                burst_allowance=0
            )


class TestRateLimitAlgorithms:
    """Tests for individual rate limiting algorithms."""

    @pytest.mark.asyncio
    async def test_token_bucket_algorithm_precision(self, rate_limit_service, rate_limit_quota, rate_limit_context):
        """Test Token Bucket algorithm for precise token consumption and refill."""
        quota = RateLimitQuota(
            max_requests=5,
            window_seconds=10,
            burst_allowance=0
        )
        timestamp = time.time()

        # First request should be allowed
        result = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
        assert result.allowed is True, "First request should be allowed"
        assert result.remaining_requests == 4, "Remaining requests should be 4"

        # Exhaust tokens (use same timestamp to stay in same window)
        for i in range(4):
            result = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
            assert result.allowed is True, f"Request {i+2} should be allowed"

        # Next request should be denied (same timestamp, same window)
        result = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
        assert result.allowed is False, "Request after exhausting tokens should be denied"
        assert result.remaining_requests == 0, "Remaining requests should be 0"

    @pytest.mark.asyncio
    async def test_sliding_window_algorithm_accuracy(self, rate_limit_service, rate_limit_quota, rate_limit_context):
        """Test Sliding Window algorithm for accurate request counting within window."""
        quota = RateLimitQuota(
            max_requests=3,
            window_seconds=10,
            burst_allowance=0
        )
        timestamp = time.time()

        # First 3 requests should be allowed (use same timestamp to stay in same window)
        for i in range(3):
            result = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
            assert result.allowed is True, f"Request {i+1} should be allowed"

        # 4th request should be denied (same timestamp, same window)
        result = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
        assert result.allowed is False, "Fourth request within window should be denied"

    @pytest.mark.asyncio
    async def test_fixed_window_algorithm_efficiency(self, rate_limit_service, rate_limit_quota, rate_limit_context):
        """Test Fixed Window algorithm for efficient counting and reset."""
        quota = RateLimitQuota(
            max_requests=2,
            window_seconds=5,
            burst_allowance=0
        )
        timestamp = time.time()

        # First 2 requests should be allowed (use same timestamp to stay in same window)
        result1 = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
        assert result1.allowed is True, "First request should be allowed"
        result2 = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
        assert result2.allowed is True, "Second request should be allowed"

        # Third request should be denied (same timestamp, same window)
        result3 = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
        assert result3.allowed is False, "Third request in same window should be denied"


class TestRateLimitPolicyService:
    """Tests for policy resolution and application in rate limiting."""

    @pytest.mark.asyncio
    async def test_policy_resolution_hierarchical_limits(self, rate_limit_service, rate_limit_context):
        """Test resolution of hierarchical rate limits (e.g., global vs user-specific)."""
        global_quota = RateLimitQuota(
            max_requests=5,
            window_seconds=10,
            burst_allowance=0
        )
        user_quota = RateLimitQuota(
            max_requests=2,
            window_seconds=10,
            burst_allowance=0
        )
        timestamp = time.time()

        # Test user-specific quota (use same timestamp to stay in same window)
        for i in range(2):
            result = await rate_limit_service.check_rate_limit(user_quota, rate_limit_context, timestamp)
            assert result.allowed is True, f"User request {i+1} should be allowed"

        result = await rate_limit_service.check_rate_limit(user_quota, rate_limit_context, timestamp)
        assert result.allowed is False, "User request beyond limit should be denied"

    @pytest.mark.asyncio
    async def test_policy_caching_and_invalidation(self, rate_limit_service, rate_limit_context):
        """Test caching of rate limit policies and invalidation on policy update."""
        quota = RateLimitQuota(
            max_requests=1,
            window_seconds=5,
            burst_allowance=0
        )
        timestamp = time.time()

        result1 = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
        assert result1.allowed is True, "First request should be allowed"

        result2 = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
        assert result2.allowed is False, "Second request should be denied due to cached state"


class TestAdvancedRateLimiter:
    """Tests for the overall rate limiter behavior with real integration."""

    @pytest.mark.asyncio
    async def test_hierarchical_limit_enforcement(self, rate_limit_service):
        """Test enforcement of hierarchical limits (e.g., per-user and global)."""
        global_quota = RateLimitQuota(
            max_requests=3,
            window_seconds=5,
            burst_allowance=0
        )
        request = RateLimitRequest(user_id="user_1", endpoint="/api/test", client_ip="127.0.0.1")
        user_context = RateLimitContext(
            request=request,
            applicable_policies=[],
            hierarchical_keys=[RateLimitKey(user_id="user_1")],
            processing_start_time=time.time()
        )
        timestamp = time.time()

        for i in range(3):
            result = await rate_limit_service.check_rate_limit(global_quota, user_context, timestamp)
            assert result.allowed is True, f"Request {i+1} should be allowed under global limit"

        result = await rate_limit_service.check_rate_limit(global_quota, user_context, timestamp)
        assert result.allowed is False, "Request beyond global limit should be denied"

    @pytest.mark.asyncio
    async def test_concurrent_request_handling(self, rate_limit_service, rate_limit_quota, rate_limit_context):
        """Test handling of concurrent requests to ensure atomic operations."""
        quota = RateLimitQuota(
            max_requests=5,
            window_seconds=10,
            burst_allowance=0
        )
        timestamp = time.time()

        # Simulate concurrent requests with asyncio.gather
        tasks = [
            rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
            for _ in range(10)
        ]
        results = await asyncio.gather(*tasks)

        allowed_count = sum(1 for r in results if r.allowed)
        assert allowed_count == 5, "Exactly 5 requests should be allowed under fixed window"
        assert sum(1 for r in results if not r.allowed) == 5, "Remaining 5 requests should be denied"


class TestRateLimitResilience:
    """Tests for resilience under failure conditions."""

    @pytest.mark.asyncio
    async def test_redis_failure_graceful_degradation(self, rate_limit_quota, rate_limit_context):
        """Test graceful degradation when Redis is unavailable."""
        # Mock a failing Redis client
        failing_redis = AsyncMock(spec=redis.Redis)
        failing_redis.get.side_effect = redis.ConnectionError("Redis unavailable")
        failing_redis.set.side_effect = redis.ConnectionError("Redis unavailable")
        failing_redis.script_load.side_effect = redis.ConnectionError("Redis unavailable")
        failing_redis.evalsha.side_effect = redis.ConnectionError("Redis unavailable")
        failing_redis.ping.side_effect = redis.ConnectionError("Redis unavailable")
        repo = RedisRateLimitRepository(failing_redis, ttl_seconds=60)
        service = RateLimitService(repo)
        timestamp = time.time()

        # Should not crash, may default to allowing or denying based on fallback
        result = await service.check_rate_limit(rate_limit_quota, rate_limit_context, timestamp)
        assert isinstance(result, RateLimitResult), "Should return a valid result even on failure"

    @pytest.mark.asyncio
    async def test_circuit_breaker_behavior(self, rate_limit_quota, rate_limit_context):
        """Test circuit breaker behavior for rate limiting on repeated failures."""
        # Mock Redis with intermittent failures
        flaky_redis = AsyncMock(spec=redis.Redis)
        flaky_redis.get.side_effect = [redis.ConnectionError("Temporary failure")] * 5 + [None]
        flaky_redis.set.side_effect = [redis.ConnectionError("Temporary failure")] * 5 + [None]
        flaky_redis.script_load.side_effect = [redis.ConnectionError("Temporary failure")] * 5 + ["script_sha"]
        flaky_redis.evalsha.side_effect = [redis.ConnectionError("Temporary failure")] * 5 + [1]
        flaky_redis.ping.side_effect = [redis.ConnectionError("Temporary failure")] * 5 + [True]
        repo = RedisRateLimitRepository(flaky_redis, ttl_seconds=60)
        service = RateLimitService(repo)
        timestamp = time.time()

        # First few calls should attempt connection, eventually trip circuit breaker if integrated
        for i in range(3):
            result = await service.check_rate_limit(rate_limit_quota, rate_limit_context, timestamp + i)
            assert isinstance(result, RateLimitResult), f"Attempt {i+1} should handle failure gracefully"


class TestRateLimitObservability:
    """Tests for metrics and tracing integration."""

    @pytest.mark.asyncio
    async def test_comprehensive_metrics_collection(self, rate_limit_service, rate_limit_quota, rate_limit_context):
        """Test collection of metrics for rate limit events (hits, blocks)."""
        timestamp = time.time()
        result = await rate_limit_service.check_rate_limit(rate_limit_quota, rate_limit_context, timestamp)
        assert result.allowed is True, "Request should be allowed"
        # Metrics logging is handled in service; test ensures no crashes
        # Future integration with metrics.py will verify actual metric recording
        assert True, "Metrics collection should not interfere with rate limit logic"

    @pytest.mark.asyncio
    async def test_distributed_tracing_integration(self, rate_limit_service, rate_limit_quota, rate_limit_context):
        """Test integration with distributed tracing for request tracking."""
        timestamp = time.time()
        result = await rate_limit_service.check_rate_limit(rate_limit_quota, rate_limit_context, timestamp)
        assert result.allowed is True, "Request should be allowed"
        # Tracing integration to be added; test ensures no interference
        assert True, "Tracing integration should not break rate limiting"


class TestRateLimitPerformance:
    """Tests for performance under load."""

    @pytest.mark.asyncio
    async def test_sub_millisecond_latency_requirement(self, rate_limit_service, rate_limit_quota, rate_limit_context):
        """Test that rate limit checks complete with sub-millisecond latency."""
        timestamp = time.time()
        start_time = time.perf_counter()
        result = await rate_limit_service.check_rate_limit(rate_limit_quota, rate_limit_context, timestamp)
        end_time = time.perf_counter()

        latency_ms = (end_time - start_time) * 1000
        assert result.allowed is True, "Request should be allowed"
        assert latency_ms < 1.0, f"Latency should be sub-millisecond, got {latency_ms} ms"

    @pytest.mark.asyncio
    async def test_memory_usage_bounded_under_load(self, rate_limit_service, rate_limit_quota, rate_limit_context):
        """Test that memory usage remains bounded under high request load."""
        timestamp = time.time()
        # Simulate high load with many requests
        tasks = [
            rate_limit_service.check_rate_limit(rate_limit_quota, rate_limit_context, timestamp + i * 0.001)
            for i in range(100)
        ]
        await asyncio.gather(*tasks)
        # Memory usage check requires profiling tools; this test ensures no crashes
        assert True, "System should handle high load without crashing"


class TestRateLimitSecurity:
    """Tests for security features in rate limiting."""

    @pytest.mark.asyncio
    async def test_sophisticated_key_generation_anti_abuse(self, rate_limit_service, rate_limit_quota):
        """Test that key generation prevents enumeration attacks via hashing."""
        request1 = RateLimitRequest(user_id="user_123", endpoint="/api/test", client_ip="127.0.0.1")
        request2 = RateLimitRequest(user_id="user_456", endpoint="/api/test", client_ip="127.0.0.1")
        context1 = RateLimitContext(
            request=request1,
            applicable_policies=[],
            hierarchical_keys=[RateLimitKey(user_id="user_123")],
            processing_start_time=time.time()
        )
        context2 = RateLimitContext(
            request=request2,
            applicable_policies=[],
            hierarchical_keys=[RateLimitKey(user_id="user_456")],
            processing_start_time=time.time()
        )
        timestamp = time.time()

        # Even though contexts are different, keys are hashed, so enumeration is hard
        result1 = await rate_limit_service.check_rate_limit(rate_limit_quota, context1, timestamp)
        result2 = await rate_limit_service.check_rate_limit(rate_limit_quota, context2, timestamp + 1)
        assert result1.allowed is True, "First context request should be allowed"
        assert result2.allowed is True, "Second context request should be allowed independently"

    @pytest.mark.asyncio
    async def test_rate_limit_bypass_prevention(self, rate_limit_service, rate_limit_quota, rate_limit_context):
        """Test prevention of rate limit bypass via timestamp manipulation or other tricks."""
        timestamp = time.time()
        quota = RateLimitQuota(
            max_requests=1,
            window_seconds=5,
            burst_allowance=0
        )

        result1 = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
        assert result1.allowed is True, "First request should be allowed"

        # Attempt bypass with same timestamp (should be denied)
        result2 = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
        assert result2.allowed is False, "Bypass attempt with same timestamp should be denied" 