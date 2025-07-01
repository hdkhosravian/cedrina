"""Rate Limiting Configuration

Centralized configuration for rate limiting policies, allowing easy adjustment
of limits without code changes. Supports environment-based configuration
for different deployment environments.
"""

from typing import List, Optional, Set

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.core.rate_limiting.entities import RateLimitPolicy
from src.core.rate_limiting.value_objects import RateLimitAlgorithm, RateLimitQuota


class RateLimitingConfig(BaseSettings):
    """Configuration for rate limiting system."""

    # Global settings
    enable_rate_limiting: bool = Field(True, alias="RATE_LIMITING_ENABLED")
    fail_open_on_error: bool = Field(True, alias="RATE_LIMITING_FAIL_OPEN")
    cache_ttl_seconds: int = Field(300, alias="RATE_LIMITING_CACHE_TTL")

    # Disable functionality
    disable_rate_limiting: bool = Field(False, alias="RATE_LIMITING_DISABLED")
    disable_for_ips: Set[str] = Field(default_factory=set, alias="RATE_LIMITING_DISABLE_IPS")
    disable_for_users: Set[str] = Field(default_factory=set, alias="RATE_LIMITING_DISABLE_USERS")
    disable_for_endpoints: Set[str] = Field(
        default_factory=set, alias="RATE_LIMITING_DISABLE_ENDPOINTS"
    )
    disable_for_user_tiers: Set[str] = Field(
        default_factory=set, alias="RATE_LIMITING_DISABLE_TIERS"
    )
    emergency_disable: bool = Field(False, alias="RATE_LIMITING_EMERGENCY_DISABLE")

    # Tier-based limits (requests per minute)
    free_tier_limit: int = Field(60, alias="RATE_LIMIT_FREE_TIER")
    premium_tier_limit: int = Field(300, alias="RATE_LIMIT_PREMIUM_TIER")
    api_tier_limit: int = Field(1000, alias="RATE_LIMIT_API_TIER")

    # Endpoint-specific limits
    auth_endpoint_limit: int = Field(10, alias="RATE_LIMIT_AUTH_ENDPOINT")
    registration_limit: int = Field(3, alias="RATE_LIMIT_REGISTRATION")

    # Algorithm preferences
    default_algorithm: str = Field("token_bucket", alias="RATE_LIMITING_ALGORITHM")

    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="RATE_LIMITING_", extra="ignore", populate_by_name=True
    )

    @field_validator(
        "disable_for_ips",
        "disable_for_users",
        "disable_for_endpoints",
        "disable_for_user_tiers",
        mode="before",
    )
    @classmethod
    def parse_comma_separated_sets(cls, v):
        """Parse comma-separated strings into sets."""
        if isinstance(v, str):
            return {item.strip() for item in v.split(",") if item.strip()}
        elif isinstance(v, (list, set)):
            return set(v)
        return set()

    def is_rate_limiting_disabled(self) -> bool:
        """Check if rate limiting is globally disabled."""
        return self.disable_rate_limiting or self.emergency_disable or not self.enable_rate_limiting

    def should_bypass_rate_limit(
        self,
        client_ip: Optional[str] = None,
        user_id: Optional[str] = None,
        endpoint: Optional[str] = None,
        user_tier: Optional[str] = None,
    ) -> bool:
        """Determine if rate limiting should be bypassed for a specific request.

        Args:
            client_ip: Client IP address
            user_id: User identifier
            endpoint: API endpoint path
            user_tier: User tier (free, premium, api, etc.)

        Returns:
            True if rate limiting should be bypassed, False otherwise

        """
        # Check global disable
        if self.is_rate_limiting_disabled():
            return True

        # Check IP-based bypass
        if client_ip and client_ip in self.disable_for_ips:
            return True

        # Check user-based bypass
        if user_id and user_id in self.disable_for_users:
            return True

        # Check endpoint-based bypass
        if endpoint and endpoint in self.disable_for_endpoints:
            return True

        # Check tier-based bypass
        if user_tier and user_tier in self.disable_for_user_tiers:
            return True

        return False

    def get_bypass_reason(
        self,
        client_ip: Optional[str] = None,
        user_id: Optional[str] = None,
        endpoint: Optional[str] = None,
        user_tier: Optional[str] = None,
    ) -> Optional[str]:
        """Get the reason why rate limiting is being bypassed.

        Returns:
            String describing the bypass reason, or None if no bypass

        """
        if self.disable_rate_limiting:
            return "Rate limiting globally disabled via RATE_LIMITING_DISABLED"

        if self.emergency_disable:
            return "Rate limiting disabled via emergency override (RATE_LIMITING_EMERGENCY_DISABLE)"

        if not self.enable_rate_limiting:
            return "Rate limiting globally disabled via RATE_LIMITING_ENABLED=false"

        if client_ip and client_ip in self.disable_for_ips:
            return f"Rate limiting disabled for IP: {client_ip}"

        if user_id and user_id in self.disable_for_users:
            return f"Rate limiting disabled for user: {user_id}"

        if endpoint and endpoint in self.disable_for_endpoints:
            return f"Rate limiting disabled for endpoint: {endpoint}"

        if user_tier and user_tier in self.disable_for_user_tiers:
            return f"Rate limiting disabled for tier: {user_tier}"

        return None

    def create_policies(self) -> List[RateLimitPolicy]:
        """Create rate limiting policies from configuration."""
        # If rate limiting is disabled, return empty policies
        if self.is_rate_limiting_disabled():
            return []

        policies = []

        # Free tier policy
        free_policy = RateLimitPolicy(
            algorithm=RateLimitAlgorithm.FIXED_WINDOW,
            name="free_tier",
            user_tiers=["free"],
            priority=100,
        )
        free_policy.add_quota(
            "user",
            RateLimitQuota(max_requests=self.free_tier_limit, window_seconds=60, burst_allowance=5),
        )
        policies.append(free_policy)

        # Premium tier policy
        premium_policy = RateLimitPolicy(
            algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
            name="premium_tier",
            user_tiers=["premium"],
            priority=90,
        )
        premium_policy.add_quota(
            "user",
            RateLimitQuota(
                max_requests=self.premium_tier_limit, window_seconds=60, burst_allowance=20
            ),
        )
        policies.append(premium_policy)

        # API tier policy
        api_policy = RateLimitPolicy(
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            name="api_tier",
            user_tiers=["api"],
            priority=80,
        )
        api_policy.add_quota(
            "user",
            RateLimitQuota(max_requests=self.api_tier_limit, window_seconds=60, burst_allowance=50),
        )
        policies.append(api_policy)

        # Authentication endpoint protection
        auth_policy = RateLimitPolicy(
            algorithm=RateLimitAlgorithm.FIXED_WINDOW,
            name="auth_protection",
            endpoints=["/api/v1/auth/login", "/api/v1/auth/register"],
            priority=50,
        )
        auth_policy.add_quota(
            "endpoint",
            RateLimitQuota(
                max_requests=self.auth_endpoint_limit,
                window_seconds=300,  # 5 minutes
                burst_allowance=0,
            ),
        )
        policies.append(auth_policy)

        return policies


# Global configuration instance
rate_limiting_config = RateLimitingConfig()
