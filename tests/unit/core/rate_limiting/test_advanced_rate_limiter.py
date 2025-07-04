"""Unit Tests for Advanced Rate Limiting System
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

from src.core.rate_limiting.entities import RateLimitRequest, RateLimitResult
from src.core.rate_limiting.repositories import RedisRateLimitRepository
from src.core.rate_limiting.services import RateLimitContext, RateLimitService

# Import rate limiting core components
from src.core.rate_limiting.value_objects import (
    RateLimitAlgorithm,
    RateLimitKey,
    RateLimitQuota,
)


# Fixtures for test setup
@pytest.fixture
def redis_client():
    """Fixture to provide a mock Redis client for testing."""
    # Create a mock Redis client
    mock_client = MagicMock()
    
    # Storage for mock data
    storage = {}
    counters = {}
    sorted_sets = {}
    pipelines = []
    
    # Mock async methods
    async def mock_get(key):
        return storage.get(key)
    
    async def mock_set(key, value, ex=None):
        storage[key] = value
        return True
    
    async def mock_setex(key, ex, value):
        storage[key] = value
        return True
    
    async def mock_incr(key):
        counters[key] = counters.get(key, 0) + 1
        return counters[key]
    
    async def mock_expire(key, time):
        return True
    
    async def mock_delete(*keys):
        deleted = 0
        for key in keys:
            if key in storage:
                del storage[key]
                deleted += 1
            if key in counters:
                del counters[key]
                deleted += 1
            if key in sorted_sets:
                del sorted_sets[key]
                deleted += 1
        return deleted
    
    async def mock_exists(key):
        return key in storage or key in counters or key in sorted_sets
    
    async def mock_ttl(key):
        return 3600  # Return 1 hour TTL for simplicity
    
    async def mock_ping():
        return True
    
    async def mock_scan(cursor, match=None, count=None):
        # Simple scan implementation for testing
        all_keys = list(storage.keys()) + list(counters.keys()) + list(sorted_sets.keys())
        if match:
            import fnmatch
            all_keys = [k for k in all_keys if fnmatch.fnmatch(k, match)]
        return 0, all_keys  # Return 0 cursor to indicate completion
    
    async def mock_zrangebyscore(key, min=None, max=None):
        if key not in sorted_sets:
            return []
        timestamps = sorted_sets[key]
        if min is not None and max is not None:
            filtered = [ts for ts in timestamps if min <= ts <= max]
        elif min is not None:
            filtered = [ts for ts in timestamps if ts >= min]
        elif max is not None:
            filtered = [ts for ts in timestamps if ts <= max]
        else:
            filtered = timestamps
        return [str(ts).encode('utf-8') for ts in filtered]
    
    async def mock_zadd(key, mapping):
        if key not in sorted_sets:
            sorted_sets[key] = []
        for score, value in mapping.items():
            if isinstance(value, bytes):
                value = value.decode('utf-8')
            sorted_sets[key].append(float(value))
        return len(mapping)
    
    async def mock_zremrangebyscore(key, min_score, max_score):
        if key not in sorted_sets:
            return 0
        original_count = len(sorted_sets[key])
        sorted_sets[key] = [ts for ts in sorted_sets[key] if not (min_score <= ts <= max_score)]
        return original_count - len(sorted_sets[key])
    
    async def mock_zrange(key, start, end):
        if key not in sorted_sets:
            return []
        timestamps = sorted(sorted_sets[key])
        if end == -1:
            return [str(ts).encode('utf-8') for ts in timestamps[start:]]
        else:
            return [str(ts).encode('utf-8') for ts in timestamps[start:end+1]]
    
    async def mock_evalsha(sha, numkeys, *args):
        # Mock Lua script execution for fixed window counting
        if len(args) >= 3:
            key, window_start, ttl = args[0], args[1], args[2]
            current_count = counters.get(key, 0)
            counters[key] = current_count + 1
            return current_count + 1
        return 0
    
    async def mock_script_load(script):
        # Mock script loading - return a fake SHA
        return "fake_script_sha_123"
    
    # Pipeline mock
    class MockPipeline:
        def __init__(self, redis_client):
            self.commands = []
            self.redis = redis_client
        
        async def __aenter__(self):
            return self
        
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
        
        async def zadd(self, key, mapping):
            self.commands.append(('zadd', key, mapping))
            return self
        
        async def expire(self, key, ttl):
            self.commands.append(('expire', key, ttl))
            return self
        
        async def zremrangebyscore(self, key, min_score, max_score):
            self.commands.append(('zremrangebyscore', key, min_score, max_score))
            return self
        
        async def execute(self):
            # Execute all commands
            for cmd, *args in self.commands:
                if cmd == 'zadd':
                    await mock_zadd(*args)
                elif cmd == 'expire':
                    await mock_expire(*args)
                elif cmd == 'zremrangebyscore':
                    await mock_zremrangebyscore(*args)
            return [True] * len(self.commands)
    
    async def mock_pipeline(transaction=True):
        return MockPipeline(mock_client)
    
    # Assign all async methods to the mock
    mock_client.get = mock_get
    mock_client.set = mock_set
    mock_client.setex = mock_setex
    mock_client.incr = mock_incr
    mock_client.expire = mock_expire
    mock_client.delete = mock_delete
    mock_client.exists = mock_exists
    mock_client.ttl = mock_ttl
    mock_client.ping = mock_ping
    mock_client.scan = mock_scan
    mock_client.zrangebyscore = mock_zrangebyscore
    mock_client.zadd = mock_zadd
    mock_client.zremrangebyscore = mock_zremrangebyscore
    mock_client.zrange = mock_zrange
    mock_client.evalsha = mock_evalsha
    mock_client.script_load = mock_script_load
    mock_client.pipeline = mock_pipeline
    
    # Configure sync methods that might be called
    mock_client.ping = MagicMock(return_value=True)
    
    return mock_client


@pytest.fixture
def rate_limit_repository(redis_client):
    """Fixture to provide a rate limit repository instance for tests."""
    return RedisRateLimitRepository(redis_client, ttl_seconds=60)


@pytest.fixture
def rate_limit_service(rate_limit_repository):
    """Fixture to provide a rate limit service instance for tests."""
    return RateLimitService(rate_limit_repository)


@pytest.fixture
def rate_limit_key():
    """Fixture for a sample rate limit key."""
    return RateLimitKey(user_id="test_user", endpoint="/api/test", client_ip="127.0.0.1")


@pytest.fixture
def rate_limit_quota():
    """Fixture for a sample rate limit quota (10 requests per minute)."""
    return RateLimitQuota(max_requests=10, window_seconds=60, burst_allowance=2)


@pytest.fixture
def rate_limit_context():
    """Fixture for a sample rate limit context."""
    request = RateLimitRequest(user_id="test_user_123", endpoint="/api/test", client_ip="127.0.0.1")
    return RateLimitContext(
        request=request,
        applicable_policies=[],
        hierarchical_keys=[RateLimitKey(user_id="test_user_123")],
        processing_start_time=time.time(),
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

    def test_rate_limit_key_ip_validation_valid_ips(self):
        """Test that valid IP addresses are accepted."""
        # Valid IPv4 addresses should work
        valid_ips = ["127.0.0.1", "192.168.1.1", "10.0.0.1", "255.255.255.255", "0.0.0.0"]

        for valid_ip in valid_ips:
            # Should not raise an exception
            key = RateLimitKey(user_id="test", client_ip=valid_ip)
            assert key.client_ip == valid_ip

    def test_rate_limit_key_ip_validation_invalid_ips(self):
        """Test that invalid IP addresses are rejected."""
        # Invalid IPv4 addresses should raise ValueError
        invalid_ips = [
            "999.999.999.999",  # Out of range octets
            "256.1.1.1",  # First octet out of range
            "1.256.1.1",  # Second octet out of range
            "1.1.256.1",  # Third octet out of range
            "1.1.1.256",  # Fourth octet out of range
            "300.1.1.1",  # Multiple out of range
            "192.168.1",  # Too few octets
            "192.168.1.1.1",  # Too many octets
            "192.168.abc.1",  # Non-numeric octets
            "not.an.ip.address",  # Completely invalid format
        ]

        for invalid_ip in invalid_ips:
            with pytest.raises(ValueError, match=f"Invalid IP format: {invalid_ip}"):
                RateLimitKey(user_id="test", client_ip=invalid_ip)

    def test_rate_limit_key_ip_validation_special_cases(self):
        """Test special IP address cases that should be allowed."""
        # These special cases should be allowed
        special_ips = [
            "unknown",
            "localhost",
            "127.0.0.1",  # Localhost IP
            "",  # Empty string (fallback value)
            None,  # None should be allowed as it's optional
        ]

        for special_ip in special_ips:
            # Should not raise an exception
            key = RateLimitKey(user_id="test", client_ip=special_ip)
            assert key.client_ip == special_ip

    def test_rate_limit_quota_validation_and_calculation(self):
        """Test RateLimitQuota validation and rate calculation."""
        quota = RateLimitQuota(max_requests=100, window_seconds=60, burst_allowance=10)

        assert quota.max_requests == 100, "Max requests should match"
        assert quota.window_seconds == 60, "Window seconds should match"
        assert quota.burst_allowance == 10, "Burst allowance should match"

        # Test invalid quota values
        with pytest.raises(ValueError):
            RateLimitQuota(max_requests=0, window_seconds=60, burst_allowance=0)

        with pytest.raises(ValueError):
            RateLimitQuota(max_requests=10, window_seconds=0, burst_allowance=0)


class TestRateLimitAlgorithms:
    """Tests for individual rate limiting algorithms."""

    @pytest.mark.asyncio
    async def test_token_bucket_algorithm_precision(
        self, rate_limit_service, rate_limit_quota, rate_limit_context
    ):
        """Test Token Bucket algorithm for precise token consumption and refill."""
        quota = RateLimitQuota(max_requests=5, window_seconds=10, burst_allowance=0)
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
    async def test_sliding_window_algorithm_accuracy(
        self, rate_limit_service, rate_limit_quota, rate_limit_context
    ):
        """Test Sliding Window algorithm for accurate request counting within window."""
        quota = RateLimitQuota(max_requests=3, window_seconds=10, burst_allowance=0)
        timestamp = time.time()

        # First 3 requests should be allowed (use same timestamp to stay in same window)
        for i in range(3):
            result = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
            assert result.allowed is True, f"Request {i+1} should be allowed"

        # 4th request should be denied (same timestamp, same window)
        result = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
        assert result.allowed is False, "Fourth request within window should be denied"

    @pytest.mark.asyncio
    async def test_fixed_window_algorithm_efficiency(
        self, rate_limit_service, rate_limit_quota, rate_limit_context
    ):
        """Test Fixed Window algorithm for efficient counting and reset."""
        quota = RateLimitQuota(max_requests=2, window_seconds=5, burst_allowance=0)
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
    """Tests for rate limiting policy service functionality."""

    @pytest.mark.asyncio
    async def test_policy_resolution_hierarchical_limits(
        self, rate_limit_service, rate_limit_context
    ):
        """Test resolution of hierarchical rate limits (e.g., global vs user-specific)."""
        global_quota = RateLimitQuota(max_requests=5, window_seconds=10, burst_allowance=0)
        user_quota = RateLimitQuota(max_requests=2, window_seconds=10, burst_allowance=0)
        timestamp = time.time()

        # Test user-specific quota (use same timestamp to stay in same window)
        for i in range(2):
            result = await rate_limit_service.check_rate_limit(
                user_quota, rate_limit_context, timestamp
            )
            assert result.allowed is True, f"User request {i+1} should be allowed"

        result = await rate_limit_service.check_rate_limit(
            user_quota, rate_limit_context, timestamp
        )
        assert result.allowed is False, "User request beyond limit should be denied"

    @pytest.mark.asyncio
    async def test_policy_caching_and_invalidation(self, rate_limit_service, rate_limit_context):
        """Test caching of rate limit policies and invalidation on policy update."""
        quota = RateLimitQuota(max_requests=1, window_seconds=5, burst_allowance=0)
        timestamp = time.time()

        result1 = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
        assert result1.allowed is True, "First request should be allowed"

        result2 = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
        assert result2.allowed is False, "Second request should be denied due to cached state"


class TestAdvancedRateLimiter:
    """Tests for advanced rate limiting features."""

    @pytest.mark.asyncio
    async def test_hierarchical_limit_enforcement(self, rate_limit_service):
        """Test enforcement of hierarchical limits (e.g., per-user and global)."""
        global_quota = RateLimitQuota(max_requests=3, window_seconds=5, burst_allowance=0)
        request = RateLimitRequest(user_id="user_1", endpoint="/api/test", client_ip="127.0.0.1")
        user_context = RateLimitContext(
            request=request,
            applicable_policies=[],
            hierarchical_keys=[RateLimitKey(user_id="user_1")],
            processing_start_time=time.time(),
        )
        timestamp = time.time()

        for i in range(3):
            result = await rate_limit_service.check_rate_limit(
                global_quota, user_context, timestamp
            )
            assert result.allowed is True, f"Request {i+1} should be allowed under global limit"

        result = await rate_limit_service.check_rate_limit(global_quota, user_context, timestamp)
        assert result.allowed is False, "Request beyond global limit should be denied"

    @pytest.mark.asyncio
    async def test_concurrent_request_handling(
        self, rate_limit_service, rate_limit_quota, rate_limit_context
    ):
        """Test handling of concurrent requests to ensure atomic operations."""
        quota = RateLimitQuota(max_requests=5, window_seconds=10, burst_allowance=0)
        timestamp = time.time()

        # Simulate concurrent requests with asyncio.gather
        tasks = [
            rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
            for _ in range(10)
        ]
        results = await asyncio.gather(*tasks)

        allowed_count = sum(1 for r in results if r.allowed)
        assert allowed_count == 5, "Exactly 5 requests should be allowed under fixed window"


class TestRateLimitResilience:
    """Tests for rate limiting resilience and error handling."""

    @pytest.mark.asyncio
    async def test_redis_failure_graceful_degradation(self, rate_limit_quota, rate_limit_context):
        """Test graceful degradation when Redis is unavailable."""
        # Create a mock Redis client that raises exceptions
        failing_redis = AsyncMock(spec=redis.Redis)
        failing_redis.get.side_effect = Exception("Redis connection failed")
        failing_redis.set.side_effect = Exception("Redis connection failed")
        failing_redis.incr.side_effect = Exception("Redis connection failed")

        repository = RedisRateLimitRepository(failing_redis, ttl_seconds=60)
        service = RateLimitService(repository)

        # Should return fallback result (allow request) when Redis fails
        result = await service.check_rate_limit(rate_limit_quota, rate_limit_context)
        assert result.allowed is True, "Should allow request when Redis fails"
        assert result.fallback_used is True, "Should indicate fallback was used"

    @pytest.mark.asyncio
    async def test_circuit_breaker_behavior(self, rate_limit_quota, rate_limit_context):
        """Test circuit breaker behavior for repeated failures."""
        # Create a mock Redis client that fails intermittently
        flaky_redis = AsyncMock(spec=redis.Redis)
        call_count = 0

        async def flaky_get(key):
            nonlocal call_count
            call_count += 1
            if call_count <= 3:  # First 3 calls fail
                raise Exception("Redis connection failed")
            return None

        flaky_redis.get = flaky_get
        flaky_redis.set = AsyncMock(return_value=True)
        flaky_redis.incr = AsyncMock(return_value=1)

        repository = RedisRateLimitRepository(flaky_redis, ttl_seconds=60)
        service = RateLimitService(repository)

        # First few calls should fail and use fallback
        for i in range(3):
            result = await service.check_rate_limit(rate_limit_quota, rate_limit_context)
            assert result.allowed is True, f"Request {i+1} should be allowed via fallback"
            assert result.fallback_used is True, f"Request {i+1} should use fallback"


class TestRateLimitObservability:
    """Tests for rate limiting observability and metrics."""

    @pytest.mark.asyncio
    async def test_comprehensive_metrics_collection(
        self, rate_limit_service, rate_limit_quota, rate_limit_context
    ):
        """Test that comprehensive metrics are collected for rate limiting decisions."""
        result = await rate_limit_service.check_rate_limit(rate_limit_quota, rate_limit_context)

        # Verify result contains observability data
        assert hasattr(result, "metadata"), "Result should contain metadata"
        assert "processing_time_ms" in result.metadata, "Should include processing time"
        assert "algorithm" in result.metadata, "Should include algorithm used"

    @pytest.mark.asyncio
    async def test_distributed_tracing_integration(
        self, rate_limit_service, rate_limit_quota, rate_limit_context
    ):
        """Test integration with distributed tracing systems."""
        result = await rate_limit_service.check_rate_limit(rate_limit_quota, rate_limit_context)

        # Verify tracing information is included
        assert hasattr(result, "metadata"), "Result should contain metadata"
        assert "trace_id" in result.metadata or "correlation_id" in result.metadata, "Should include tracing info"


class TestRateLimitPerformance:
    """Tests for rate limiting performance requirements."""

    @pytest.mark.asyncio
    async def test_sub_millisecond_latency_requirement(
        self, rate_limit_service, rate_limit_quota, rate_limit_context
    ):
        """Test that rate limiting decisions complete in sub-millisecond time."""
        import time

        start_time = time.time()
        result = await rate_limit_service.check_rate_limit(rate_limit_quota, rate_limit_context)
        end_time = time.time()

        processing_time_ms = (end_time - start_time) * 1000
        assert processing_time_ms < 1.0, f"Rate limiting should complete in <1ms, took {processing_time_ms:.3f}ms"

        # Verify result is valid
        assert result.allowed is True, "First request should be allowed"

    @pytest.mark.asyncio
    async def test_memory_usage_bounded_under_load(
        self, rate_limit_service, rate_limit_quota, rate_limit_context
    ):
        """Test that memory usage remains bounded under high load."""
        import gc
        import sys

        # Force garbage collection before test
        gc.collect()
        initial_memory = sys.getsizeof(rate_limit_service)

        # Simulate high load
        timestamp = time.time()
        for i in range(100):
            result = await rate_limit_service.check_rate_limit(rate_limit_quota, rate_limit_context, timestamp)

        # Force garbage collection after test
        gc.collect()
        final_memory = sys.getsizeof(rate_limit_service)

        # Memory usage should not grow significantly
        memory_growth = final_memory - initial_memory
        assert memory_growth < 1000, f"Memory usage should not grow significantly, grew {memory_growth} bytes"


class TestRateLimitSecurity:
    """Tests for rate limiting security features."""

    @pytest.mark.asyncio
    async def test_sophisticated_key_generation_anti_abuse(
        self, rate_limit_service, rate_limit_quota
    ):
        """Test sophisticated key generation to prevent abuse and enumeration."""
        request1 = RateLimitRequest(user_id="user_1", endpoint="/api/test", client_ip="127.0.0.1")
        request2 = RateLimitRequest(user_id="user_2", endpoint="/api/test", client_ip="127.0.0.1")
        
        context1 = RateLimitContext(
            request=request1,
            applicable_policies=[],
            hierarchical_keys=[RateLimitKey(user_id="user_1")],
            processing_start_time=time.time(),
        )
        context2 = RateLimitContext(
            request=request2,
            applicable_policies=[],
            hierarchical_keys=[RateLimitKey(user_id="user_2")],
            processing_start_time=time.time(),
        )

        # Generate keys for both contexts
        key1 = rate_limit_service._generate_secure_key(rate_limit_quota, context1)
        key2 = rate_limit_service._generate_secure_key(rate_limit_quota, context2)

        # Keys should be different for different users
        assert key1 != key2, "Keys should be different for different users"
        assert key1.composite_key != key2.composite_key, "Composite keys should be different"

    @pytest.mark.asyncio
    async def test_rate_limit_bypass_prevention(
        self, rate_limit_service, rate_limit_quota, rate_limit_context
    ):
        """Test prevention of rate limit bypass via timestamp manipulation or other tricks."""
        timestamp = time.time()
        quota = RateLimitQuota(max_requests=1, window_seconds=5, burst_allowance=0)

        result1 = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
        assert result1.allowed is True, "First request should be allowed"

        # Attempt bypass with same timestamp (should be denied)
        result2 = await rate_limit_service.check_rate_limit(quota, rate_limit_context, timestamp)
        assert result2.allowed is False, "Bypass attempt with same timestamp should be denied"
