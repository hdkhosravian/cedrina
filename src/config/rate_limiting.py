"""
Rate Limiting Configuration

Centralized configuration for rate limiting policies, allowing easy adjustment
of limits without code changes. Supports environment-based configuration
for different deployment environments.
"""

from typing import Dict, List
from pydantic import BaseSettings, Field
from src.domain.rate_limiting.entities import RateLimitPolicy
from src.domain.rate_limiting.value_objects import RateLimitQuota, RateLimitAlgorithm


class RateLimitingConfig(BaseSettings):
    """Configuration for rate limiting system."""
    
    # Global settings
    enable_rate_limiting: bool = Field(True, env="RATE_LIMITING_ENABLED")
    fail_open_on_error: bool = Field(True, env="RATE_LIMITING_FAIL_OPEN")
    cache_ttl_seconds: int = Field(300, env="RATE_LIMITING_CACHE_TTL")
    
    # Tier-based limits (requests per minute)
    free_tier_limit: int = Field(60, env="RATE_LIMIT_FREE_TIER")
    premium_tier_limit: int = Field(300, env="RATE_LIMIT_PREMIUM_TIER")
    api_tier_limit: int = Field(1000, env="RATE_LIMIT_API_TIER")
    
    # Endpoint-specific limits
    auth_endpoint_limit: int = Field(10, env="RATE_LIMIT_AUTH_ENDPOINT")
    registration_limit: int = Field(3, env="RATE_LIMIT_REGISTRATION")
    
    # Algorithm preferences
    default_algorithm: str = Field("token_bucket", env="RATE_LIMITING_ALGORITHM")
    
    class Config:
        env_file = ".env"
        env_prefix = "RATE_LIMITING_"
    
    def create_policies(self) -> List[RateLimitPolicy]:
        """Create rate limiting policies from configuration."""
        policies = []
        
        # Free tier policy
        free_policy = RateLimitPolicy(
            algorithm=RateLimitAlgorithm.FIXED_WINDOW,
            name="free_tier",
            user_tiers=["free"],
            priority=100
        )
        free_policy.add_quota("user", RateLimitQuota(
            max_requests=self.free_tier_limit,
            window_seconds=60,
            burst_allowance=5
        ))
        policies.append(free_policy)
        
        # Premium tier policy
        premium_policy = RateLimitPolicy(
            algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
            name="premium_tier",
            user_tiers=["premium"],
            priority=90
        )
        premium_policy.add_quota("user", RateLimitQuota(
            max_requests=self.premium_tier_limit,
            window_seconds=60,
            burst_allowance=20
        ))
        policies.append(premium_policy)
        
        # API tier policy
        api_policy = RateLimitPolicy(
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            name="api_tier",
            user_tiers=["api"],
            priority=80
        )
        api_policy.add_quota("user", RateLimitQuota(
            max_requests=self.api_tier_limit,
            window_seconds=60,
            burst_allowance=50
        ))
        policies.append(api_policy)
        
        # Authentication endpoint protection
        auth_policy = RateLimitPolicy(
            algorithm=RateLimitAlgorithm.FIXED_WINDOW,
            name="auth_protection",
            endpoints=["/api/v1/auth/login", "/api/v1/auth/register"],
            priority=50
        )
        auth_policy.add_quota("endpoint", RateLimitQuota(
            max_requests=self.auth_endpoint_limit,
            window_seconds=300,  # 5 minutes
            burst_allowance=0
        ))
        policies.append(auth_policy)
        
        return policies


# Global configuration instance
rate_limiting_config = RateLimitingConfig() 