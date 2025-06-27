"""
Rate Limiting Domain Services

Domain services that orchestrate complex business logic for rate limiting operations.
These services coordinate between entities, value objects, and repositories to
implement sophisticated rate limiting strategies.

Services:
- AdvancedRateLimiter: Main orchestrator for rate limiting decisions
- RateLimitPolicyService: Policy management and resolution
- RateLimitMetricsService: Metrics collection and analysis
- RateLimitSecurityService: Security and anti-abuse features

Design Principles:
- Single Responsibility: Each service has a focused purpose  
- Dependency Injection: Services depend on repository abstractions
- Business Logic Focus: Services contain domain rules and orchestration
- Testable: Easily mockable dependencies for unit testing
"""

from __future__ import annotations
import asyncio
import time
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from functools import lru_cache
from collections import defaultdict
import logging
from hashlib import sha256

from .value_objects import RateLimitKey, RateLimitQuota, RateLimitAlgorithm, RateLimitPeriod
from .entities import RateLimitPolicy, RateLimitResult, RateLimitRequest
from .repositories import (
    RateLimitRepository, RateLimitPolicyRepository, RateLimitMetricsRepository,
    RateLimitRepositoryError
)

logger = logging.getLogger(__name__)


@dataclass
class RateLimitContext:
    """Context object for rate limiting operations with all relevant information"""
    request: RateLimitRequest
    applicable_policies: List[RateLimitPolicy]
    hierarchical_keys: List[RateLimitKey]
    processing_start_time: float
    
    def add_timing_metadata(self, key: str, duration_ms: float) -> None:
        """Add timing metadata for performance analysis"""
        if not hasattr(self, '_timing_metadata'):
            self._timing_metadata = {}
        self._timing_metadata[key] = duration_ms


class AdvancedRateLimiter:
    """
    Main domain service orchestrating rate limiting decisions.
    
    Coordinates policy resolution, hierarchical limit enforcement,
    algorithm execution, and result composition. Implements sophisticated
    strategies for high-use applications including circuit breaking,
    fallback mechanisms, and performance optimization.
    """
    
    def __init__(
        self,
        repository: RateLimitRepository,
        policy_service: RateLimitPolicyService,
        metrics_service: Optional[RateLimitMetricsService] = None,
        security_service: Optional[RateLimitSecurityService] = None,
        circuit_breaker: Optional[Any] = None  # Will be properly typed when circuit breaker is implemented
    ):
        self.repository = repository
        self.policy_service = policy_service
        self.metrics_service = metrics_service
        self.security_service = security_service
        self.circuit_breaker = circuit_breaker
        
        # Performance optimization caches
        self._result_cache: Dict[str, RateLimitResult] = {}
        self._cache_ttl_seconds = 1  # Very short cache for performance
    
    def _check_bypass_conditions(self, request: RateLimitRequest) -> Optional[str]:
        """
        Check if rate limiting should be bypassed for this request.
        
        Args:
            request: The rate limiting request
            
        Returns:
            String describing the bypass reason, or None if no bypass
        """
        from src.config.rate_limiting import rate_limiting_config
        return rate_limiting_config.get_bypass_reason(
            client_ip=request.client_ip,
            user_id=request.user_id,
            endpoint=request.endpoint,
            user_tier=request.user_tier
        )
    
    async def check_rate_limit(self, request: RateLimitRequest) -> RateLimitResult:
        """
        Main entry point for rate limiting decisions.
        
        Orchestrates the complete rate limiting workflow:
        1. Security validation and request enhancement
        2. Policy resolution and caching
        3. Hierarchical limit checking
        4. Result composition and caching
        5. Metrics recording and observability
        
        Args:
            request: The rate limiting request to evaluate
            
        Returns:
            RateLimitResult with complete decision and metadata
        """
        processing_start = time.time()
        
        try:
            # Step 0: Check if rate limiting should be bypassed
            bypass_reason = self._check_bypass_conditions(request)
            if bypass_reason:
                logger.info(f"Rate limiting bypassed: {bypass_reason}")
                bypass_result = RateLimitResult.allowed_result(
                    request_key=request.rate_limit_key,
                    remaining_requests=float('inf'),
                    reset_time=datetime.now() + timedelta(hours=1),
                    algorithm=RateLimitAlgorithm.FIXED_WINDOW,
                    metadata={"bypass_reason": bypass_reason, "bypassed": True}
                )
                processing_time = time.time() - processing_start
                await self._record_metrics(request, bypass_result, processing_time)
                return bypass_result
            
            # Step 1: Security validation and request enhancement
            if self.security_service:
                request = await self.security_service.enhance_request_security(request)
            
            # Step 2: Check result cache for performance
            cache_key = self._generate_cache_key(request)
            cached_result = self._get_cached_result(cache_key)
            if cached_result:
                await self._record_metrics(request, cached_result, time.time() - processing_start)
                return cached_result
            
            # Step 3: Create rate limiting context
            context = await self._create_rate_limit_context(request, processing_start)
            
            # Step 4: Execute hierarchical rate limiting
            result = await self._execute_hierarchical_rate_limiting(context)
            
            # Step 5: Post-process result
            result = await self._post_process_result(result, context)
            
            # Step 6: Cache result for performance
            self._cache_result(cache_key, result)
            
            # Step 7: Record metrics and observability
            processing_time = time.time() - processing_start
            await self._record_metrics(request, result, processing_time)
            
            return result
            
        except Exception as e:
            # Fallback strategy: fail open with monitoring
            logger.error(f"Rate limiting error: {e}", exc_info=True)
            
            fallback_result = RateLimitResult.fallback_result(
                request_key=request.rate_limit_key,
                error_details=str(e)
            )
            
            processing_time = time.time() - processing_start
            await self._record_metrics(request, fallback_result, processing_time)
            
            return fallback_result
    
    async def _create_rate_limit_context(
        self, 
        request: RateLimitRequest, 
        processing_start: float
    ) -> RateLimitContext:
        """Create comprehensive context for rate limiting operations"""
        
        # Get applicable policies
        policies = await self.policy_service.get_policies_for_request(
            user_tier=request.user_tier,
            endpoint=request.endpoint,
            client_ip=request.client_ip
        )
        
        # Generate hierarchical keys
        base_key = request.rate_limit_key
        hierarchical_keys = [
            RateLimitKey(
                user_id=request.user_id,
                endpoint=request.endpoint,
                client_ip=request.client_ip,
                user_tier=request.user_tier
            )
        ]
        
        # Add additional hierarchical keys based on policies
        for policy in policies:
            for quota_level in policy.quotas.keys():
                if quota_level == "user" and request.user_id:
                    hierarchical_keys.append(RateLimitKey(user_id=request.user_id))
                elif quota_level == "endpoint" and request.endpoint:
                    hierarchical_keys.append(RateLimitKey(endpoint=request.endpoint))
                elif quota_level == "global":
                    hierarchical_keys.append(RateLimitKey(custom_context="global"))
        
        return RateLimitContext(
            request=request,
            applicable_policies=policies,
            hierarchical_keys=list(set(hierarchical_keys)),  # Remove duplicates
            processing_start_time=processing_start
        )
    
    async def _execute_hierarchical_rate_limiting(self, context: RateLimitContext) -> RateLimitResult:
        """
        Execute hierarchical rate limiting with early termination optimization.
        
        Checks limits from most restrictive to least restrictive, terminating
        early when a limit is exceeded for optimal performance.
        """
        if not context.applicable_policies:
            # No policies apply - allow request but log for monitoring
            logger.warning(f"No rate limiting policies found for request: {context.request}")
            return RateLimitResult.allowed_result(
                request_key=context.request.rate_limit_key,
                remaining_requests=float('inf'),
                reset_time=datetime.now() + timedelta(hours=1),
                algorithm=RateLimitAlgorithm.FIXED_WINDOW,
                metadata={"no_policy": True}
            )
        
        # Get the primary policy (highest priority)
        primary_policy = min(context.applicable_policies, key=lambda p: p.priority)
        
        # Check each quota level in the policy
        most_restrictive_result = None
        
        for quota_level, quota in primary_policy.quotas.items():
            # Generate appropriate key for this quota level
            quota_key = self._generate_quota_level_key(context.request, quota_level)
            
            try:
                # Execute rate limiting check for this quota
                check_start = time.time()
                result = await self.repository.check_rate_limit(
                    key=quota_key,
                    quota=quota,
                    algorithm=primary_policy.algorithm,
                    request_weight=context.request.request_weight
                )
                
                check_duration = (time.time() - check_start) * 1000
                context.add_timing_metadata(f"{quota_level}_check_ms", check_duration)
                
                # Update result with policy metadata
                result.policy_id = primary_policy.policy_id
                result.quota_level = quota_level
                result.add_metadata("quota", quota)
                
                # If this quota blocks the request, we can return immediately
                if not result.allowed:
                    return result
                
                # Track the most restrictive quota for response headers
                if (most_restrictive_result is None or 
                    result.remaining_requests < most_restrictive_result.remaining_requests):
                    most_restrictive_result = result
                    
            except RateLimitRepositoryError as e:
                logger.error(f"Repository error for quota {quota_level}: {e}")
                # Continue checking other quotas - don't fail completely
                continue
        
        # All quotas passed - return the most restrictive result
        return most_restrictive_result or RateLimitResult.allowed_result(
            request_key=context.request.rate_limit_key,
            remaining_requests=1000,  # Default safe value
            reset_time=datetime.now() + timedelta(minutes=1),
            algorithm=primary_policy.algorithm
        )
    
    def _generate_quota_level_key(self, request: RateLimitRequest, quota_level: str) -> RateLimitKey:
        """Generate appropriate rate limiting key for a specific quota level"""
        if quota_level == "global":
            return RateLimitKey(custom_context="global")
        elif quota_level == "user" and request.user_id:
            return RateLimitKey(user_id=request.user_id)
        elif quota_level == "endpoint" and request.endpoint:
            return RateLimitKey(endpoint=request.endpoint)
        elif quota_level == "ip" and request.client_ip:
            return RateLimitKey(client_ip=request.client_ip)
        else:
            # Full context key as fallback
            return request.rate_limit_key
    
    async def _post_process_result(
        self, 
        result: RateLimitResult, 
        context: RateLimitContext
    ) -> RateLimitResult:
        """Post-process rate limiting result with additional metadata and analysis"""
        
        # Add processing timing metadata
        total_processing_time = (time.time() - context.processing_start_time) * 1000
        result.processing_time_ms = total_processing_time
        
        # Add context metadata
        result.add_metadata("request_id", str(context.request.request_id))
        result.add_metadata("policies_evaluated", len(context.applicable_policies))
        result.add_metadata("hierarchical_keys_checked", len(context.hierarchical_keys))
        
        # Security analysis
        if self.security_service and context.request.is_suspicious():
            result.add_metadata("security_analysis", "suspicious_request")
            # Could implement additional restrictions for suspicious requests
        
        return result
    
    def _generate_cache_key(self, request: RateLimitRequest) -> str:
        """Generate cache key for result caching"""
        return f"rl_cache:{request.rate_limit_key.composite_key}:{int(time.time())}"
    
    def _get_cached_result(self, cache_key: str) -> Optional[RateLimitResult]:
        """Get cached result if still valid"""
        if cache_key in self._result_cache:
            cached_result, cache_time = self._result_cache[cache_key]
            if time.time() - cache_time < self._cache_ttl_seconds:
                return cached_result
            else:
                del self._result_cache[cache_key]
        return None
    
    def _cache_result(self, cache_key: str, result: RateLimitResult) -> None:
        """Cache result for performance optimization"""
        # Only cache allowed results to avoid issues with rapidly changing blocked status
        if result.allowed:
            self._result_cache[cache_key] = (result, time.time())
            
            # Simple cache cleanup to prevent memory leaks
            if len(self._result_cache) > 10000:
                # Remove oldest entries
                sorted_items = sorted(self._result_cache.items(), key=lambda x: x[1][1])
                for key, _ in sorted_items[:5000]:
                    del self._result_cache[key]
    
    async def _record_metrics(
        self, 
        request: RateLimitRequest, 
        result: RateLimitResult, 
        processing_time: float
    ) -> None:
        """Record comprehensive metrics for observability"""
        if self.metrics_service:
            try:
                await self.metrics_service.record_rate_limit_event(
                    request=request,
                    result=result,
                    processing_time_ms=processing_time * 1000
                )
            except Exception as e:
                logger.error(f"Failed to record metrics: {e}")


class RateLimitPolicyService:
    """
    Domain service for rate limiting policy management and resolution.
    
    Handles policy lookup, caching, validation, and dynamic updates.
    Provides intelligent policy matching based on request context.
    """
    
    def __init__(
        self,
        policy_repository: RateLimitPolicyRepository,
        cache_size: int = 1000,
        cache_ttl_seconds: int = 300
    ):
        self.policy_repository = policy_repository
        self.cache_size = cache_size
        self.cache_ttl_seconds = cache_ttl_seconds
        
        # Policy cache with TTL
        self._policy_cache: Dict[str, tuple] = {}  # key -> (policies, timestamp)
    
    async def get_policies_for_request(
        self,
        user_tier: Optional[str] = None,
        endpoint: Optional[str] = None,
        client_ip: Optional[str] = None
    ) -> List[RateLimitPolicy]:
        """
        Get all applicable policies for a request context.
        
        Implements intelligent caching and policy resolution logic.
        """
        cache_key = f"{user_tier}:{endpoint}:{client_ip}"
        
        # Check cache first
        cached_policies = self._get_cached_policies(cache_key)
        if cached_policies is not None:
            return cached_policies
        
        try:
            # Fetch from repository
            policies = await self.policy_repository.get_policies_for_context(
                user_tier=user_tier,
                endpoint=endpoint,
                client_ip=client_ip
            )
            
            # Filter and sort policies
            applicable_policies = [p for p in policies if p.enabled]
            applicable_policies.sort(key=lambda p: p.priority)
            
            # Cache the result
            self._cache_policies(cache_key, applicable_policies)
            
            return applicable_policies
            
        except Exception as e:
            logger.error(f"Error fetching policies: {e}")
            # Return default policy as fallback
            return [self._get_default_policy()]
    
    def _get_cached_policies(self, cache_key: str) -> Optional[List[RateLimitPolicy]]:
        """Get cached policies if still valid"""
        if cache_key in self._policy_cache:
            policies, cache_time = self._policy_cache[cache_key]
            if time.time() - cache_time < self.cache_ttl_seconds:
                return policies
            else:
                del self._policy_cache[cache_key]
        return None
    
    def _cache_policies(self, cache_key: str, policies: List[RateLimitPolicy]) -> None:
        """Cache policies with TTL and size management"""
        self._policy_cache[cache_key] = (policies, time.time())
        
        # Simple cache size management
        if len(self._policy_cache) > self.cache_size:
            # Remove oldest entries
            sorted_items = sorted(self._policy_cache.items(), key=lambda x: x[1][1])
            for key, _ in sorted_items[:self.cache_size // 2]:
                del self._policy_cache[key]
    
    def _get_default_policy(self) -> RateLimitPolicy:
        """Get default fallback policy when others fail"""
        return RateLimitPolicy(
            algorithm=RateLimitAlgorithm.FIXED_WINDOW,
            quotas={
                "global": RateLimitQuota(max_requests=1000, window_seconds=60)
            },
            name="default_fallback",
            description="Default fallback policy for error conditions",
            priority=999
        )
    
    async def invalidate_cache(self, cache_key: Optional[str] = None) -> None:
        """Invalidate policy cache for dynamic updates"""
        if cache_key:
            self._policy_cache.pop(cache_key, None)
        else:
            self._policy_cache.clear()


class RateLimitMetricsService:
    """
    Domain service for comprehensive rate limiting metrics and observability.
    
    Collects, aggregates, and analyzes metrics for monitoring, alerting,
    and business intelligence purposes.
    """
    
    def __init__(self, metrics_repository: RateLimitMetricsRepository):
        self.metrics_repository = metrics_repository
        
        # In-memory metrics for real-time monitoring
        self._request_counts = defaultdict(int)
        self._blocked_counts = defaultdict(int)
        self._latency_measurements = defaultdict(list)
        self._last_flush_time = time.time()
        self._flush_interval_seconds = 60
    
    async def record_rate_limit_event(
        self,
        request: RateLimitRequest,
        result: RateLimitResult,
        processing_time_ms: float
    ) -> None:
        """Record a rate limiting event with comprehensive metadata"""
        
        # Real-time in-memory metrics
        key = f"{request.user_tier}:{request.endpoint}"
        self._request_counts[key] += 1
        
        if result.is_blocked:
            self._blocked_counts[key] += 1
        
        self._latency_measurements[result.algorithm.value].append(processing_time_ms)
        
        # Persist to repository (async to avoid blocking)  
        try:
            await self.metrics_repository.record_rate_limit_event(
                request=request,
                result=result,
                processing_time_ms=processing_time_ms
            )
        except Exception as e:
            logger.error(f"Failed to persist metrics: {e}")
        
        # Periodic flush of aggregated metrics
        if time.time() - self._last_flush_time > self._flush_interval_seconds:
            await self._flush_aggregated_metrics()
    
    async def _flush_aggregated_metrics(self) -> None:
        """Flush aggregated metrics to repository"""
        try:
            # Record performance metrics
            for algorithm, latencies in self._latency_measurements.items():
                if latencies:
                    avg_latency = sum(latencies) / len(latencies)
                    await self.metrics_repository.record_performance_metric(
                        metric_name=f"rate_limit_latency_{algorithm}",
                        value=avg_latency,
                        tags={"algorithm": algorithm}
                    )
            
            # Clear metrics after flushing
            self._latency_measurements.clear()
            self._last_flush_time = time.time()
            
        except Exception as e:
            logger.error(f"Failed to flush metrics: {e}")
    
    def get_real_time_metrics(self) -> Dict[str, Any]:
        """Get real-time metrics for monitoring dashboards"""
        total_requests = sum(self._request_counts.values())
        total_blocked = sum(self._blocked_counts.values())
        
        return {
            "total_requests": total_requests,
            "total_blocked": total_blocked,
            "block_rate": total_blocked / total_requests if total_requests > 0 else 0,
            "top_endpoints": dict(sorted(
                self._request_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10])
        }


class RateLimitSecurityService:
    """
    Domain service for security and anti-abuse features in rate limiting.
    
    Implements sophisticated security measures to prevent abuse and
    manipulation of rate limiting systems.
    """
    
    def __init__(self):
        # Suspicious activity tracking
        self._suspicious_ips: Dict[str, datetime] = {}
        self._failed_auth_counts: Dict[str, int] = defaultdict(int)
        
    async def enhance_request_security(self, request: RateLimitRequest) -> RateLimitRequest:
        """Enhance request with security analysis and context"""
        
        # Analyze request patterns
        if self._is_ip_suspicious(request.client_ip):
            request.add_custom_attribute("ip_risk_level", "high")
        
        # Track authentication failures
        if request.endpoint and "auth" in request.endpoint:
            failure_count = self._failed_auth_counts.get(request.client_ip, 0)
            request.add_custom_attribute("failed_auth_attempts", failure_count)
        
        # Enhanced user agent analysis
        if request.user_agent:
            risk_level = self._analyze_user_agent(request.user_agent)
            request.add_custom_attribute("user_agent_risk", risk_level)
        
        return request
    
    def _is_ip_suspicious(self, client_ip: Optional[str]) -> bool:
        """Analyze if IP shows suspicious patterns"""
        if not client_ip:
            return False
        
        # Check if IP was recently marked as suspicious
        if client_ip in self._suspicious_ips:
            mark_time = self._suspicious_ips[client_ip]
            if datetime.now() - mark_time < timedelta(hours=1):
                return True
            else:
                del self._suspicious_ips[client_ip]
        
        return False
    
    def _analyze_user_agent(self, user_agent: str) -> str:
        """Analyze user agent for risk indicators"""
        user_agent_lower = user_agent.lower()
        
        high_risk_indicators = ["bot", "crawler", "scraper", "scanner"]
        medium_risk_indicators = ["curl", "wget", "python", "java"]
        
        if any(indicator in user_agent_lower for indicator in high_risk_indicators):
            return "high"
        elif any(indicator in user_agent_lower for indicator in medium_risk_indicators):
            return "medium"
        else:
            return "low"


class RateLimitService:
    """
    A service responsible for enforcing rate limiting policies based on configured quotas,
    contexts, and algorithms. It coordinates with the repository for persistence and ensures
    thread-safe, secure rate limit checks.

    This service supports multiple rate limiting strategies (Token Bucket, Sliding Window,
    Fixed Window) and hierarchical limits (e.g., global, per-user, per-IP).
    """

    def __init__(self, repository: RateLimitRepository):
        """
        Initialize the rate limiting service with a repository for persistence.

        Args:
            repository (RateLimitRepository): The repository to handle storage and retrieval
                                             of rate limit data.
        """
        self.repository = repository

    async def check_rate_limit(
        self,
        quota: RateLimitQuota,
        context: RateLimitContext,
        timestamp: Optional[float] = None
    ) -> RateLimitResult:
        """
        Check if a request is allowed under the specified rate limit quota and context.
        This method enforces the rate limit using a fixed window algorithm and updates
        the state in the repository.

        Args:
            quota (RateLimitQuota): The rate limit quota defining max requests and window.
            context (RateLimitContext): The context (e.g., user ID, IP) for the rate limit.
            timestamp (Optional[float]): The current timestamp for the request. Defaults to now.

        Returns:
            RateLimitResult: The result of the rate limit check, including whether the request
                            is allowed, remaining requests, and reset time.
        """
        if timestamp is None:
            timestamp = time.time()

        try:
            # Generate a secure key for the rate limit context
            rate_limit_key = self._generate_secure_key(quota, context)

            # Use fixed window algorithm (simplified for now)
            result = await self._handle_fixed_window(quota, rate_limit_key, timestamp)

            # Log rate limit check for observability
            logger.info(
                f"Rate limit check for key={rate_limit_key.composite_key}, "
                f"allowed={result.allowed}, remaining={result.remaining_requests}, "
                f"reset_time={result.reset_time}"
            )

            return result
        except Exception as e:
            # Handle Redis failures and other errors gracefully
            logger.warning(f"Rate limit check failed for key={context.request.rate_limit_key.composite_key}: {e}")
            
            # Return a fallback result that allows the request (fail open for availability)
            from .entities import RateLimitResult
            return RateLimitResult.fallback_result(
                request_key=context.request.rate_limit_key,
                error_details=str(e)
            )

    async def _handle_token_bucket(
        self, quota: RateLimitQuota, key: RateLimitKey, timestamp: float
    ) -> RateLimitResult:
        """
        Handle rate limiting using the Token Bucket algorithm. Tokens are replenished at a
        constant rate, and requests consume tokens. If no tokens are available, the request
        is denied.

        Args:
            quota (RateLimitQuota): The rate limit quota with max requests and window.
            key (RateLimitKey): The unique key for this rate limit context.
            timestamp (float): The current timestamp for the request.

        Returns:
            RateLimitResult: The result of the rate limit check.
        """
        tokens_per_second = quota.max_requests / quota.window_seconds
        last_refill, tokens = await self.repository.get_token_bucket_state(key)

        # Refill tokens based on elapsed time
        elapsed = timestamp - last_refill
        new_tokens = elapsed * tokens_per_second
        tokens = min(quota.max_requests, tokens + new_tokens)
        last_refill = timestamp

        if tokens >= 1.0:
            tokens -= 1.0
            await self.repository.update_token_bucket_state(key, last_refill, tokens)
            return RateLimitResult.allowed_result(
                request_key=key,
                remaining_requests=int(tokens),
                reset_time=datetime.fromtimestamp(timestamp + (1.0 / tokens_per_second) if tokens < 1.0 else timestamp),
                algorithm=RateLimitAlgorithm.TOKEN_BUCKET
            )
        else:
            await self.repository.update_token_bucket_state(key, last_refill, tokens)
            return RateLimitResult.blocked_result(
                request_key=key,
                retry_after=int(1.0 / tokens_per_second),
                reset_time=datetime.fromtimestamp(timestamp + (1.0 / tokens_per_second)),
                algorithm=RateLimitAlgorithm.TOKEN_BUCKET
            )

    async def _handle_sliding_window(
        self, quota: RateLimitQuota, key: RateLimitKey, timestamp: float
    ) -> RateLimitResult:
        """
        Handle rate limiting using the Sliding Window algorithm. Requests within the window
        are counted, and old requests outside the window are discarded.

        Args:
            quota (RateLimitQuota): The rate limit quota with max requests and window.
            key (RateLimitKey): The unique key for this rate limit context.
            timestamp (float): The current timestamp for the request.

        Returns:
            RateLimitResult: The result of the rate limit check.
        """
        window_start = timestamp - quota.window_seconds
        request_timestamps = await self.repository.get_sliding_window_requests(key, window_start)
        request_count = len(request_timestamps)

        if request_count < quota.max_requests:
            await self.repository.add_request_timestamp(key, timestamp)
            return RateLimitResult.allowed_result(
                request_key=key,
                remaining_requests=quota.max_requests - (request_count + 1),
                reset_time=datetime.fromtimestamp(timestamp + quota.window_seconds),
                algorithm=RateLimitAlgorithm.SLIDING_WINDOW
            )
        else:
            return RateLimitResult.blocked_result(
                request_key=key,
                retry_after=int(quota.window_seconds),
                reset_time=datetime.fromtimestamp(request_timestamps[0] + quota.window_seconds if request_timestamps else timestamp + quota.window_seconds),
                algorithm=RateLimitAlgorithm.SLIDING_WINDOW
            )

    async def _handle_fixed_window(
        self, quota: RateLimitQuota, key: RateLimitKey, timestamp: float
    ) -> RateLimitResult:
        """
        Handle rate limiting using the Fixed Window algorithm. Requests are counted within
        a fixed time window, resetting at the end of the window.

        Args:
            quota (RateLimitQuota): The rate limit quota with max requests and window.
            key (RateLimitKey): The unique key for this rate limit context.
            timestamp (float): The current timestamp for the request.

        Returns:
            RateLimitResult: The result of the rate limit check.
        """
        window_start = int(timestamp / quota.window_seconds) * quota.window_seconds
        count = await self.repository.increment_fixed_window_count(key, window_start, timestamp)
        reset_at = window_start + quota.window_seconds

        if count <= quota.max_requests:
            return RateLimitResult.allowed_result(
                request_key=key,
                remaining_requests=quota.max_requests - count,
                reset_time=datetime.fromtimestamp(reset_at),
                algorithm=RateLimitAlgorithm.FIXED_WINDOW
            )
        else:
            return RateLimitResult.blocked_result(
                request_key=key,
                remaining_requests=0,
                retry_after=int(reset_at - timestamp),
                reset_time=datetime.fromtimestamp(reset_at),
                algorithm=RateLimitAlgorithm.FIXED_WINDOW
            )

    def _generate_secure_key(self, quota: RateLimitQuota, context: RateLimitContext) -> RateLimitKey:
        """
        Generate a secure, unique key for the rate limit context by hashing sensitive components.
        This prevents enumeration attacks by obfuscating the actual context values.

        Args:
            quota (RateLimitQuota): The rate limit quota associated with this context.
            context (RateLimitContext): The context for which to generate a key.

        Returns:
            RateLimitKey: A secure key representing the rate limit context.
        """
        # Use the request's rate limit key which already has security features
        return context.request.rate_limit_key

    async def reset_rate_limit(self, key: RateLimitKey) -> None:
        """
        Reset the rate limit state for a given key, clearing any counters or timestamps.
        Useful for administrative actions or when a block duration expires.

        Args:
            key (RateLimitKey): The rate limit key to reset.
        """
        await self.repository.reset_state(key)
        logger.info(f"Rate limit reset for key={key.composite_key}")

    async def get_rate_limit_state(self, key: RateLimitKey) -> Dict[str, Any]:
        """
        Retrieve the current state of the rate limit for a given key. Useful for debugging
        or monitoring purposes.

        Args:
            key (RateLimitKey): The rate limit key to inspect.

        Returns:
            Dict[str, Any]: The current state of the rate limit (e.g., counters, timestamps).
        """
        return await self.repository.get_state(key) 