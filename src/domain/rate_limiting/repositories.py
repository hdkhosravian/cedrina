"""
Rate Limiting Domain Repositories

Repository interfaces defining contracts for data persistence and retrieval
in the rate limiting domain. These interfaces follow the Repository pattern
and Dependency Inversion Principle from DDD.

Repositories:
- RateLimitRepository: Core rate limiting operations
- RateLimitPolicyRepository: Policy management and retrieval
- RateLimitMetricsRepository: Metrics and observability data

Design Principles:
- Interface Segregation: Focused, single-purpose interfaces
- Dependency Inversion: Domain depends on abstractions, not implementations
- Testability: Interfaces can be easily mocked for testing
- Persistence Agnostic: No coupling to specific storage technologies
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
import redis.asyncio as redis
import json

from .value_objects import RateLimitKey, RateLimitQuota, RateLimitAlgorithm
from .entities import RateLimitPolicy, RateLimitResult, RateLimitRequest


class RateLimitRepository(ABC):
    """
    Repository interface for core rate limiting operations.
    
    Defines the contract for checking and updating rate limits using
    various algorithms. Implementations handle the specific storage
    technology (Redis, in-memory, etc.) and algorithm logic.
    """
    
    @abstractmethod
    async def check_rate_limit(
        self,
        key: RateLimitKey,
        quota: RateLimitQuota,
        algorithm: RateLimitAlgorithm,
        request_weight: int = 1
    ) -> RateLimitResult:
        """
        Check if a request should be allowed based on rate limiting rules.
        
        Args:
            key: The rate limiting key identifying the context
            quota: The quota configuration to enforce
            algorithm: The algorithm to use for rate limiting
            request_weight: How much this request counts towards the limit
            
        Returns:
            RateLimitResult indicating whether request is allowed
            
        Raises:
            RateLimitRepositoryError: When the operation fails
        """
        pass
    
    @abstractmethod
    async def reset_rate_limit(self, key: RateLimitKey) -> bool:
        """
        Reset the rate limit for a specific key.
        
        Args:
            key: The rate limiting key to reset
            
        Returns:
            True if reset was successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def get_current_usage(self, key: RateLimitKey) -> Optional[Dict[str, Any]]:
        """
        Get current usage statistics for a rate limiting key.
        
        Args:
            key: The rate limiting key to query
            
        Returns:
            Dictionary with usage statistics or None if not found
        """
        pass
    
    @abstractmethod
    async def cleanup_expired_keys(self, older_than: datetime) -> int:
        """
        Clean up expired rate limiting keys to prevent memory leaks.
        
        Args:
            older_than: Clean up keys older than this timestamp
            
        Returns:
            Number of keys cleaned up
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform a health check on the rate limiting storage.
        
        Returns:
            Health status information including latency, errors, etc.
        """
        pass

    @abstractmethod
    async def get_token_bucket_state(self, key: 'RateLimitKey') -> Tuple[float, float]:
        """
        Retrieve the token bucket state (last refill timestamp and token count) for a key.

        Args:
            key (RateLimitKey): The unique key for the rate limit context.

        Returns:
            Tuple[float, float]: Last refill timestamp and current token count.
        """
        pass

    @abstractmethod
    async def update_token_bucket_state(self, key: 'RateLimitKey', last_refill: float, tokens: float) -> None:
        """
        Update the token bucket state for a key.

        Args:
            key (RateLimitKey): The unique key for the rate limit context.
            last_refill (float): The timestamp of the last token refill.
            tokens (float): The current number of tokens.
        """
        pass

    @abstractmethod
    async def get_sliding_window_requests(self, key: 'RateLimitKey', window_start: float) -> List[float]:
        """
        Retrieve request timestamps within the sliding window for a key.

        Args:
            key (RateLimitKey): The unique key for the rate limit context.
            window_start (float): The start timestamp of the sliding window.

        Returns:
            List[float]: List of request timestamps within the window.
        """
        pass

    @abstractmethod
    async def add_request_timestamp(self, key: 'RateLimitKey', timestamp: float) -> None:
        """
        Add a request timestamp to the sliding window for a key.

        Args:
            key (RateLimitKey): The unique key for the rate limit context.
            timestamp (float): The timestamp of the request.
        """
        pass

    @abstractmethod
    async def increment_fixed_window_count(self, key: 'RateLimitKey', window_start: float, timestamp: float) -> int:
        """
        Increment the request count for a fixed window, ensuring atomic operation.

        Args:
            key (RateLimitKey): The unique key for the rate limit context.
            window_start (float): The start timestamp of the fixed window.
            timestamp (float): The current timestamp for setting expiration.

        Returns:
            int: The updated count of requests in the window.
        """
        pass

    @abstractmethod
    async def reset_state(self, key: 'RateLimitKey') -> None:
        """
        Reset the rate limit state for a key, clearing all associated data.

        Args:
            key (RateLimitKey): The unique key for the rate limit context.
        """
        pass

    @abstractmethod
    async def get_state(self, key: 'RateLimitKey') -> Dict[str, Any]:
        """
        Retrieve the full rate limit state for a key (for debugging/monitoring).

        Args:
            key (RateLimitKey): The unique key for the rate limit context.

        Returns:
            Dict[str, Any]: The current state of the rate limit.
        """
        pass


class RateLimitPolicyRepository(ABC):
    """
    Repository interface for rate limiting policy management.
    
    Handles storage and retrieval of rate limiting policies, including
    policy versioning, caching, and dynamic updates.
    """
    
    @abstractmethod
    async def get_policy_by_id(self, policy_id: str) -> Optional[RateLimitPolicy]:
        """
        Retrieve a policy by its unique identifier.
        
        Args:
            policy_id: Unique identifier for the policy
            
        Returns:
            The policy if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def get_policies_for_context(
        self,
        user_tier: Optional[str] = None,
        endpoint: Optional[str] = None,
        client_ip: Optional[str] = None
    ) -> List[RateLimitPolicy]:
        """
        Get all policies that match the given context.
        
        Args:
            user_tier: User tier to match
            endpoint: Endpoint pattern to match
            client_ip: Client IP to match
            
        Returns:
            List of matching policies, ordered by priority
        """
        pass
    
    @abstractmethod
    async def save_policy(self, policy: RateLimitPolicy) -> RateLimitPolicy:
        """
        Save or update a rate limiting policy.
        
        Args:
            policy: The policy to save
            
        Returns:
            The saved policy with updated metadata
        """
        pass
    
    @abstractmethod
    async def delete_policy(self, policy_id: str) -> bool:
        """
        Delete a rate limiting policy.
        
        Args:
            policy_id: Unique identifier for the policy to delete
            
        Returns:
            True if deletion was successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def list_policies(
        self,
        enabled_only: bool = True,
        limit: int = 100,
        offset: int = 0
    ) -> List[RateLimitPolicy]:
        """
        List rate limiting policies with pagination.
        
        Args:
            enabled_only: Whether to return only enabled policies
            limit: Maximum number of policies to return
            offset: Number of policies to skip
            
        Returns:
            List of policies matching the criteria
        """
        pass
    
    @abstractmethod
    async def invalidate_policy_cache(self, policy_id: Optional[str] = None) -> None:
        """
        Invalidate policy cache to force reload from storage.
        
        Args:
            policy_id: Specific policy to invalidate, or None for all policies
        """
        pass


class RateLimitMetricsRepository(ABC):
    """
    Repository interface for rate limiting metrics and observability.
    
    Handles collection, storage, and retrieval of metrics data for
    monitoring, alerting, and business intelligence.
    """
    
    @abstractmethod
    async def record_rate_limit_event(
        self,
        request: RateLimitRequest,
        result: RateLimitResult,
        processing_time_ms: float
    ) -> None:
        """
        Record a rate limiting event for metrics collection.
        
        Args:
            request: The original request
            result: The rate limiting result
            processing_time_ms: Time taken to process the request
        """
        pass
    
    @abstractmethod
    async def get_metrics_summary(
        self,
        start_time: datetime,
        end_time: datetime,
        granularity: str = "minute"
    ) -> Dict[str, Any]:
        """
        Get aggregated metrics for a time period.
        
        Args:
            start_time: Start of the time range
            end_time: End of the time range
            granularity: Time granularity (minute, hour, day)
            
        Returns:
            Dictionary with aggregated metrics
        """
        pass
    
    @abstractmethod
    async def get_top_limited_keys(
        self,
        start_time: datetime,
        end_time: datetime,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get the most frequently rate-limited keys.
        
        Args:
            start_time: Start of the time range
            end_time: End of the time range
            limit: Maximum number of keys to return
            
        Returns:
            List of keys with their blocking counts
        """
        pass
    
    @abstractmethod
    async def check_alert_conditions(self) -> List[Dict[str, Any]]:
        """
        Check for alert conditions in rate limiting metrics.
        
        Returns:
            List of active alerts with details
        """
        pass
    
    @abstractmethod
    async def record_performance_metric(
        self,
        metric_name: str,
        value: float,
        tags: Dict[str, str] = None
    ) -> None:
        """
        Record a performance metric.
        
        Args:
            metric_name: Name of the metric
            value: Metric value
            tags: Optional tags for the metric
        """
        pass


class RateLimitAuditRepository(ABC):
    """
    Repository interface for audit logging of rate limiting operations.
    
    Handles storage and retrieval of audit logs for compliance,
    security analysis, and debugging purposes.
    """
    
    @abstractmethod
    async def log_rate_limit_decision(
        self,
        request: RateLimitRequest,
        result: RateLimitResult,
        policy_id: Optional[str] = None,
        additional_context: Dict[str, Any] = None
    ) -> None:
        """
        Log a rate limiting decision for audit purposes.
        
        Args:
            request: The original request
            result: The rate limiting result
            policy_id: ID of the policy that was applied
            additional_context: Additional context for the audit log
        """
        pass
    
    @abstractmethod
    async def log_policy_change(
        self,
        policy: RateLimitPolicy,
        change_type: str,
        changed_by: str,
        reason: Optional[str] = None
    ) -> None:
        """
        Log a policy change for audit purposes.
        
        Args:
            policy: The policy that was changed
            change_type: Type of change (create, update, delete)
            changed_by: User who made the change
            reason: Optional reason for the change
        """
        pass
    
    @abstractmethod
    async def get_audit_logs(
        self,
        start_time: datetime,
        end_time: datetime,
        event_type: Optional[str] = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Retrieve audit logs for a time period.
        
        Args:
            start_time: Start of the time range
            end_time: End of the time range
            event_type: Optional filter by event type
            limit: Maximum number of logs to return
            
        Returns:
            List of audit log entries
        """
        pass


# Exception classes for repository operations
class RateLimitRepositoryError(Exception):
    """Base exception for rate limiting repository operations"""
    pass


class RateLimitRepositoryConnectionError(RateLimitRepositoryError):
    """Exception raised when repository connection fails"""
    pass


class RateLimitRepositoryTimeoutError(RateLimitRepositoryError):
    """Exception raised when repository operations timeout"""
    pass


class RateLimitRepositoryDataError(RateLimitRepositoryError):
    """Exception raised when data validation fails"""
    pass


class RedisRateLimitRepository(RateLimitRepository):
    """
    A concrete implementation of RateLimitRepository using Redis for persistence.
    This repository uses Redis atomic operations (via Lua scripts or pipelines)
    to ensure thread-safe rate limiting under high concurrency.
    """

    def __init__(self, redis_client: redis.Redis, ttl_seconds: int = 3600):
        """
        Initialize the Redis-based rate limit repository.

        Args:
            redis_client (redis.Redis): The async Redis client instance.
            ttl_seconds (int): Time-to-live for Redis keys to prevent stale data buildup.
        """
        self.redis = redis_client
        self.ttl_seconds = ttl_seconds
        # Lua script for atomic fixed window increment
        self._fixed_window_script = """
        local key = KEYS[1]
        local window_start = tonumber(ARGV[1])
        local ttl = tonumber(ARGV[2])
        local current_count = redis.call('GET', key)
        if current_count == false then
            redis.call('SET', key, 1)
            redis.call('EXPIRE', key, ttl)
            return 1
        else
            redis.call('INCR', key)
            return tonumber(current_count) + 1
        end
        """
        self._fixed_window_sha = None

    async def _register_scripts(self) -> None:
        """Register Lua scripts with Redis for atomic operations."""
        if self._fixed_window_sha is None:
            self._fixed_window_sha = await self.redis.script_load(self._fixed_window_script)

    async def get_token_bucket_state(self, key: 'RateLimitKey') -> Tuple[float, float]:
        """
        Retrieve the token bucket state (last refill timestamp and token count) for a key.
        """
        token_key = f"{key.composite_key}:token_bucket"
        data = await self.redis.get(token_key)
        if data is None:
            return (0.0, 0.0)
        try:
            state = json.loads(data.decode('utf-8'))
            return (state.get('last_refill', 0.0), state.get('tokens', 0.0))
        except (json.JSONDecodeError, AttributeError):
            return (0.0, 0.0)

    async def update_token_bucket_state(self, key: 'RateLimitKey', last_refill: float, tokens: float) -> None:
        """
        Update the token bucket state for a key with TTL to prevent stale data.
        """
        token_key = f"{key.composite_key}:token_bucket"
        state = {'last_refill': last_refill, 'tokens': tokens}
        await self.redis.set(token_key, json.dumps(state), ex=self.ttl_seconds)

    async def get_sliding_window_requests(self, key: 'RateLimitKey', window_start: float) -> List[float]:
        """
        Retrieve request timestamps within the sliding window for a key.
        Uses Redis sorted sets for efficient range queries.
        """
        window_key = f"{key.composite_key}:sliding_window"
        timestamps = await self.redis.zrangebyscore(window_key, min=window_start, max='+inf')
        return [float(ts.decode('utf-8')) for ts in timestamps if ts] if timestamps else []

    async def add_request_timestamp(self, key: 'RateLimitKey', timestamp: float) -> None:
        """
        Add a request timestamp to the sliding window for a key and clean up old entries.
        """
        window_key = f"{key.composite_key}:sliding_window"
        async with self.redis.pipeline(transaction=True) as pipe:
            await pipe.zadd(window_key, {str(timestamp).encode('utf-8'): timestamp})
            await pipe.expire(window_key, self.ttl_seconds)
            await pipe.zremrangebyscore(window_key, '-inf', timestamp - self.ttl_seconds)
            await pipe.execute()

    async def increment_fixed_window_count(self, key: 'RateLimitKey', window_start: float, timestamp: float) -> int:
        """
        Increment the request count for a fixed window using a Lua script for atomicity.
        """
        window_key = f"{key.composite_key}:fixed_window:{window_start}"
        await self._register_scripts()
        ttl = int(self.ttl_seconds)
        result = await self.redis.evalsha(self._fixed_window_sha, 1, window_key, window_start, ttl)
        return int(result)

    async def reset_state(self, key: 'RateLimitKey') -> None:
        """
        Reset the rate limit state for a key by deleting all associated Redis keys.
        """
        pattern = f"{key.composite_key}:*"
        cursor = 0
        while True:
            cursor, keys = await self.redis.scan(cursor, match=pattern, count=100)
            if keys:
                await self.redis.delete(*keys)
            if cursor == 0:
                break

    async def get_state(self, key: 'RateLimitKey') -> Dict[str, Any]:
        """
        Retrieve the full rate limit state for a key across all algorithms.
        """
        state = {}
        # Token Bucket
        token_key = f"{key.composite_key}:token_bucket"
        token_data = await self.redis.get(token_key)
        if token_data:
            state['token_bucket'] = json.loads(token_data.decode('utf-8'))
        # Sliding Window
        window_key = f"{key.composite_key}:sliding_window"
        timestamps = await self.redis.zrange(window_key, 0, -1)
        if timestamps:
            state['sliding_window'] = [float(ts.decode('utf-8')) for ts in timestamps]
        # Fixed Window (approximate, may need pattern matching for multiple windows)
        pattern = f"{key.composite_key}:fixed_window:*"
        cursor = 0
        fixed_windows = {}
        while True:
            cursor, keys = await self.redis.scan(cursor, match=pattern, count=100)
            for k in keys:
                count = await self.redis.get(k)
                if count:
                    fixed_windows[k.decode('utf-8')] = int(count)
            if cursor == 0:
                break
        state['fixed_window'] = fixed_windows
        return state

    async def check_rate_limit(
        self,
        key: RateLimitKey,
        quota: RateLimitQuota,
        algorithm: RateLimitAlgorithm,
        request_weight: int = 1
    ) -> RateLimitResult:
        """
        Check if a request should be allowed based on rate limiting rules.
        """
        try:
            if algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
                return await self._check_token_bucket(key, quota, request_weight)
            elif algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
                return await self._check_sliding_window(key, quota, request_weight)
            elif algorithm == RateLimitAlgorithm.FIXED_WINDOW:
                return await self._check_fixed_window(key, quota, request_weight)
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
        except Exception as e:
            # Return a fallback result on error
            from .entities import RateLimitResult
            return RateLimitResult.fallback_result(
                request_key=key,
                error_details=str(e)
            )

    async def reset_rate_limit(self, key: RateLimitKey) -> bool:
        """
        Reset the rate limit for a specific key.
        """
        try:
            await self.reset_state(key)
            return True
        except Exception:
            return False

    async def get_current_usage(self, key: RateLimitKey) -> Optional[Dict[str, Any]]:
        """
        Get current usage statistics for a rate limiting key.
        """
        try:
            state = await self.get_state(key)
            if not state:
                return None
            
            usage = {
                'key': key.composite_key,
                'state': state,
                'last_updated': datetime.now().isoformat()
            }
            return usage
        except Exception:
            return None

    async def cleanup_expired_keys(self, older_than: datetime) -> int:
        """
        Clean up expired rate limiting keys to prevent memory leaks.
        """
        try:
            # This is a simplified cleanup - in production you'd want more sophisticated logic
            pattern = "*:rate_limit:*"
            cursor = 0
            cleaned_count = 0
            
            while True:
                cursor, keys = await self.redis.scan(cursor, match=pattern, count=100)
                for key in keys:
                    # Check if key is older than the threshold
                    ttl = await self.redis.ttl(key)
                    if ttl == -1:  # No expiration set
                        await self.redis.expire(key, self.ttl_seconds)
                        cleaned_count += 1
                if cursor == 0:
                    break
            
            return cleaned_count
        except Exception:
            return 0

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform a health check on the rate limiting storage.
        """
        try:
            start_time = datetime.now()
            await self.redis.ping()
            latency = (datetime.now() - start_time).total_seconds() * 1000
            
            return {
                'status': 'healthy',
                'latency_ms': latency,
                'connection': 'ok',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'connection': 'failed',
                'timestamp': datetime.now().isoformat()
            }

    async def _check_token_bucket(self, key: RateLimitKey, quota: RateLimitQuota, request_weight: int) -> RateLimitResult:
        """Check rate limit using token bucket algorithm."""
        from .entities import RateLimitResult
        from datetime import datetime, timedelta
        
        last_refill, tokens = await self.get_token_bucket_state(key)
        now = datetime.now().timestamp()
        
        # Calculate time since last refill
        time_passed = now - last_refill
        tokens_to_add = time_passed * (quota.max_requests / quota.window_seconds)
        
        # Refill tokens
        new_tokens = min(quota.max_requests, tokens + tokens_to_add)
        
        # Check if we have enough tokens
        if new_tokens >= request_weight:
            # Consume tokens
            remaining_tokens = new_tokens - request_weight
            await self.update_token_bucket_state(key, now, remaining_tokens)
            
            return RateLimitResult.allowed_result(
                request_key=key,
                remaining_requests=int(remaining_tokens),
                reset_time=datetime.now() + timedelta(seconds=quota.window_seconds),
                algorithm=RateLimitAlgorithm.TOKEN_BUCKET
            )
        else:
            # Not enough tokens
            return RateLimitResult.blocked_result(
                request_key=key,
                retry_after=int(quota.window_seconds),
                reset_time=datetime.now() + timedelta(seconds=quota.window_seconds),
                algorithm=RateLimitAlgorithm.TOKEN_BUCKET
            )

    async def _check_sliding_window(self, key: RateLimitKey, quota: RateLimitQuota, request_weight: int) -> RateLimitResult:
        """Check rate limit using sliding window algorithm."""
        from .entities import RateLimitResult
        from datetime import datetime, timedelta
        
        now = datetime.now().timestamp()
        window_start = now - quota.window_seconds
        
        # Get requests in current window
        requests = await self.get_sliding_window_requests(key, window_start)
        
        # Count requests in window
        current_count = len(requests)
        
        if current_count + request_weight <= quota.max_requests:
            # Add current request
            await self.add_request_timestamp(key, now)
            
            return RateLimitResult.allowed_result(
                request_key=key,
                remaining_requests=quota.max_requests - current_count - request_weight,
                reset_time=datetime.now() + timedelta(seconds=quota.window_seconds),
                algorithm=RateLimitAlgorithm.SLIDING_WINDOW
            )
        else:
            # Request would exceed limit
            return RateLimitResult.blocked_result(
                request_key=key,
                retry_after=int(quota.window_seconds),
                reset_time=datetime.now() + timedelta(seconds=quota.window_seconds),
                algorithm=RateLimitAlgorithm.SLIDING_WINDOW
            )

    async def _check_fixed_window(self, key: RateLimitKey, quota: RateLimitQuota, request_weight: int) -> RateLimitResult:
        """Check rate limit using fixed window algorithm."""
        from .entities import RateLimitResult
        from datetime import datetime, timedelta
        
        now = datetime.now().timestamp()
        window_start = int(now // quota.window_seconds) * quota.window_seconds
        
        # Increment count for current window
        current_count = await self.increment_fixed_window_count(key, window_start, now)
        
        if current_count <= quota.max_requests:
            return RateLimitResult.allowed_result(
                request_key=key,
                remaining_requests=quota.max_requests - current_count,
                reset_time=datetime.fromtimestamp(window_start + quota.window_seconds),
                algorithm=RateLimitAlgorithm.FIXED_WINDOW
            )
        else:
            return RateLimitResult.blocked_result(
                request_key=key,
                retry_after=int(window_start + quota.window_seconds - now),
                reset_time=datetime.fromtimestamp(window_start + quota.window_seconds),
                algorithm=RateLimitAlgorithm.FIXED_WINDOW
            ) 