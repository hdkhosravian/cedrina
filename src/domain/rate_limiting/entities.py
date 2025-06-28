"""Rate Limiting Domain Entities

Entities with identity that represent core business concepts in the rate limiting domain.
These objects have lifecycles, can change state, and maintain identity across operations.

Entities:
- RateLimitPolicy: Configuration and rules for rate limiting
- RateLimitResult: Result of a rate limiting operation
- RateLimitRequest: Request for rate limit checking

Design Principles:
- Identity: Each entity has a unique identifier
- Encapsulation: Business logic and invariants are protected
- Lifecycle: Entities can change state over time
- Rich Behavior: Methods that express domain operations
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from .value_objects import RateLimitAlgorithm, RateLimitKey, RateLimitQuota


@dataclass
class RateLimitPolicy:
    """Entity representing a rate limiting policy with hierarchical quotas.

    A policy defines how rate limiting should be applied for a given context,
    including the algorithm to use, hierarchical quotas (global, user, endpoint),
    and metadata for policy management.

    Business Rules:
    - Policies must have at least one quota defined
    - Algorithm must be supported by the system
    - Hierarchical quotas are enforced from most to least restrictive
    - Policies can be dynamically updated without system restart
    """

    # Core configuration (non-default fields first)
    algorithm: RateLimitAlgorithm

    # Identity (default fields after)
    policy_id: UUID = field(default_factory=uuid4)

    # Metadata
    quotas: Dict[str, RateLimitQuota] = field(default_factory=dict)
    name: Optional[str] = None
    description: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    version: int = 1

    # Policy matching criteria
    user_tiers: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    ip_ranges: List[str] = field(default_factory=list)

    # Policy behavior
    priority: int = 100  # Lower number = higher priority
    enabled: bool = True

    def __post_init__(self):
        """Validate policy configuration at creation"""
        # Allow creation without quotas initially for configuration purposes
        # Quotas will be validated when the policy is actually used
        if self.quotas:
            self._validate_quota_hierarchy()

    def _validate_quota_hierarchy(self) -> None:
        """Validate that hierarchical quotas are logically consistent"""
        if "global" in self.quotas and "user" in self.quotas:
            global_quota = self.quotas["global"]
            user_quota = self.quotas["user"]

            if user_quota.requests_per_second > global_quota.requests_per_second:
                raise ValueError("User quota cannot exceed global quota")

    def add_quota(self, level: str, quota: RateLimitQuota) -> None:
        """Add or update a quota at a specific hierarchy level"""
        if not isinstance(quota, RateLimitQuota):
            raise ValueError("Quota must be a RateLimitQuota instance")

        self.quotas[level] = quota
        self._validate_quota_hierarchy()
        self._update_version()

    def remove_quota(self, level: str) -> None:
        """Remove a quota from the policy"""
        if level in self.quotas:
            del self.quotas[level]
            self._update_version()

        if not self.quotas:
            raise ValueError("Policy must have at least one quota")

    def get_most_restrictive_quota(self) -> RateLimitQuota:
        """Get the most restrictive quota from all configured quotas.

        This is used when multiple quotas apply to determine which
        limit should be enforced.
        """
        if not self.quotas:
            raise ValueError("No quotas defined in policy")

        most_restrictive = None
        for quota in self.quotas.values():
            if most_restrictive is None or quota.is_more_restrictive_than(most_restrictive):
                most_restrictive = quota

        return most_restrictive

    def matches_request_context(
        self,
        user_tier: Optional[str] = None,
        endpoint: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> bool:
        """Check if this policy matches the given request context.

        A policy matches if any of its criteria match the request context.
        Empty criteria lists match all requests.
        """
        if not self.enabled:
            return False

        # Check user tier matching
        if self.user_tiers and user_tier:
            if user_tier not in self.user_tiers:
                return False

        # Check endpoint matching (supports wildcards)
        if self.endpoints and endpoint:
            endpoint_matches = any(
                self._endpoint_matches(endpoint, pattern) for pattern in self.endpoints
            )
            if not endpoint_matches:
                return False

        # Check IP range matching (simplified - would need proper CIDR in production)
        if self.ip_ranges and client_ip:
            ip_matches = any(self._ip_matches(client_ip, ip_range) for ip_range in self.ip_ranges)
            if not ip_matches:
                return False

        return True

    def _endpoint_matches(self, endpoint: str, pattern: str) -> bool:
        """Check if endpoint matches pattern (supports basic wildcards)"""
        if pattern == "*":
            return True
        if pattern.endswith("/*"):
            return endpoint.startswith(pattern[:-2])
        return endpoint == pattern

    def _ip_matches(self, client_ip: str, ip_range: str) -> bool:
        """Basic IP matching - would need proper CIDR implementation"""
        if ip_range == "*":
            return True
        return client_ip.startswith(ip_range.split("/")[0])

    def _update_version(self) -> None:
        """Update version and timestamp when policy changes"""
        self.version += 1
        self.updated_at = datetime.now()

    def clone_with_updates(self, **updates) -> RateLimitPolicy:
        """Create a new policy with specified updates"""
        new_policy = RateLimitPolicy(
            algorithm=self.algorithm,
            quotas=self.quotas.copy(),
            name=self.name,
            description=self.description,
            user_tiers=self.user_tiers.copy(),
            endpoints=self.endpoints.copy(),
            ip_ranges=self.ip_ranges.copy(),
            priority=self.priority,
            enabled=self.enabled,
        )

        # Apply updates
        for key, value in updates.items():
            if hasattr(new_policy, key):
                setattr(new_policy, key, value)

        return new_policy

    def validate_quotas(self) -> None:
        """Validate that the policy has at least one quota defined"""
        if not self.quotas:
            raise ValueError("Policy must have at least one quota defined")
        self._validate_quota_hierarchy()


@dataclass
class RateLimitResult:
    """Entity representing the result of a rate limiting operation.

    Contains all information about whether a request was allowed or blocked,
    including remaining capacity, reset times, and metadata for observability.

    This entity maintains identity through the request it relates to and
    provides rich information for clients and monitoring systems.
    """

    # Core result (non-default fields first)
    request_key: RateLimitKey
    allowed: bool
    remaining_requests: int
    algorithm: RateLimitAlgorithm

    # Identity and context (default fields after)
    result_id: UUID = field(default_factory=uuid4)

    # Timing information
    reset_time: Optional[datetime] = None
    retry_after: Optional[int] = None  # Seconds to wait before retrying
    window_start: Optional[datetime] = None

    # Algorithm and policy information
    policy_id: Optional[UUID] = None
    quota_level: Optional[str] = None  # Which quota was the limiting factor

    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)
    processing_time_ms: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Error handling
    fallback_used: bool = False
    error_details: Optional[str] = None

    @property
    def is_blocked(self) -> bool:
        """Check if the request was blocked"""
        return not self.allowed

    @property
    def has_remaining_capacity(self) -> bool:
        """Check if there is remaining capacity"""
        return self.remaining_requests > 0

    @property
    def reset_time_unix(self) -> Optional[int]:
        """Get reset time as Unix timestamp for HTTP headers"""
        if self.reset_time:
            return int(self.reset_time.timestamp())
        return None

    @property
    def seconds_until_reset(self) -> Optional[int]:
        """Calculate seconds until the rate limit resets"""
        if self.reset_time:
            delta = self.reset_time - datetime.now()
            return max(0, int(delta.total_seconds()))
        return None

    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to the result"""
        self.metadata[key] = value

    def to_http_headers(self) -> Dict[str, str]:
        """Convert result to HTTP headers following standard conventions.

        Returns headers suitable for including in HTTP responses:
        - X-RateLimit-Limit: The rate limit ceiling for the given request
        - X-RateLimit-Remaining: The number of requests left for the window
        - X-RateLimit-Reset: The remaining window before the rate limit resets
        - Retry-After: Number of seconds to wait (only when blocked)
        """
        headers = {}

        # Basic rate limit headers
        if self.quota_level and self.quota_level in self.metadata:
            quota = self.metadata[self.quota_level]
            if hasattr(quota, "effective_limit"):
                headers["X-RateLimit-Limit"] = str(quota.effective_limit)

        headers["X-RateLimit-Remaining"] = str(max(0, self.remaining_requests))

        if self.reset_time_unix:
            headers["X-RateLimit-Reset"] = str(self.reset_time_unix)

        # Retry-After header when blocked
        if self.is_blocked and self.retry_after:
            headers["Retry-After"] = str(self.retry_after)

        # Algorithm information
        headers["X-RateLimit-Policy"] = self.algorithm.value

        return headers

    @classmethod
    def allowed_result(
        cls,
        request_key: RateLimitKey,
        remaining_requests: int,
        reset_time: datetime,
        algorithm: RateLimitAlgorithm,
        **kwargs,
    ) -> RateLimitResult:
        """Factory method for creating allowed results"""
        return cls(
            request_key=request_key,
            allowed=True,
            remaining_requests=remaining_requests,
            reset_time=reset_time,
            algorithm=algorithm,
            **kwargs,
        )

    @classmethod
    def blocked_result(
        cls,
        request_key: RateLimitKey,
        retry_after: int,
        reset_time: datetime,
        algorithm: RateLimitAlgorithm,
        **kwargs,
    ) -> RateLimitResult:
        """Factory method for creating blocked results"""
        # Remove remaining_requests from kwargs if present to avoid duplicate
        kwargs.pop("remaining_requests", None)

        return cls(
            request_key=request_key,
            allowed=False,
            remaining_requests=0,
            retry_after=retry_after,
            reset_time=reset_time,
            algorithm=algorithm,
            **kwargs,
        )

    @classmethod
    def fallback_result(
        cls, request_key: RateLimitKey, error_details: str, **kwargs
    ) -> RateLimitResult:
        """Factory method for creating fallback results when systems fail"""
        return cls(
            request_key=request_key,
            allowed=True,  # Fail open for availability
            remaining_requests=-1,  # Indicates fallback mode
            algorithm=RateLimitAlgorithm.FIXED_WINDOW,  # Default fallback
            fallback_used=True,
            error_details=error_details,
            **kwargs,
        )


@dataclass
class RateLimitRequest:
    """Entity representing a request for rate limit checking.

    Encapsulates all context needed to perform rate limiting decisions,
    including user identity, endpoint information, and request metadata.

    This entity serves as the input to the rate limiting system and
    maintains identity for tracing and auditing purposes.
    """

    # Identity
    request_id: UUID = field(default_factory=uuid4)

    # Request context
    user_id: Optional[str] = None
    endpoint: Optional[str] = None
    client_ip: Optional[str] = None
    user_tier: Optional[str] = None

    # HTTP context
    method: Optional[str] = None
    user_agent: Optional[str] = None

    # Request metadata
    timestamp: datetime = field(default_factory=datetime.now)
    request_size: Optional[int] = None
    custom_attributes: Dict[str, Any] = field(default_factory=dict)

    # Behavioral context
    is_authenticated: bool = False
    request_weight: int = 1  # Some requests may count as multiple requests

    def __post_init__(self):
        """Validate request has minimum required information"""
        if not any([self.user_id, self.endpoint, self.client_ip]):
            raise ValueError("Request must have at least user_id, endpoint, or client_ip")

    @property
    def rate_limit_key(self) -> RateLimitKey:
        """Generate the rate limiting key for this request"""
        return RateLimitKey(
            user_id=self.user_id,
            endpoint=self.endpoint,
            client_ip=self.client_ip,
            user_tier=self.user_tier,
        )

    def add_custom_attribute(self, key: str, value: Any) -> None:
        """Add custom attribute to the request"""
        self.custom_attributes[key] = value

    def get_custom_attribute(self, key: str, default: Any = None) -> Any:
        """Get custom attribute from the request"""
        return self.custom_attributes.get(key, default)

    def is_high_priority(self) -> bool:
        """Check if this is a high-priority request that should get preferential treatment"""
        high_priority_tiers = {"enterprise", "premium"}
        high_priority_endpoints = {"/api/v1/health", "/api/v1/auth/logout"}

        return (
            self.user_tier in high_priority_tiers
            or self.endpoint in high_priority_endpoints
            or self.get_custom_attribute("high_priority", False)
        )

    def is_suspicious(self) -> bool:
        """Check if this request shows suspicious patterns that warrant stricter limiting.

        This is a placeholder for more sophisticated behavior analysis that could
        include machine learning models or rule-based detection.
        """
        suspicious_indicators = [
            self.user_agent and "bot" in self.user_agent.lower(),
            self.request_weight > 10,
            self.get_custom_attribute("failed_auth_attempts", 0) > 3,
        ]

        return any(suspicious_indicators)

    @classmethod
    def from_http_request(
        cls,
        user_id: Optional[str],
        endpoint: str,
        client_ip: str,
        method: str,
        user_agent: Optional[str] = None,
        user_tier: str = "free",
        **kwargs,
    ) -> RateLimitRequest:
        """Factory method for creating requests from HTTP context"""
        return cls(
            user_id=user_id,
            endpoint=endpoint,
            client_ip=client_ip,
            method=method,
            user_agent=user_agent,
            user_tier=user_tier,
            is_authenticated=user_id is not None,
            **kwargs,
        )
