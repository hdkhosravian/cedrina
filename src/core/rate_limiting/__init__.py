"""Rate Limiting Core Module

This module contains the core rate limiting system for an advanced, production-ready
application. It follows Domain-Driven Design principles with:

- Value Objects: Immutable objects representing rate limiting concepts
- Entities: Objects with identity that model rate limiting policies and results
- Domain Services: Business logic for rate limiting operations
- Repositories: Contracts for data persistence and retrieval

The design supports multiple algorithms, hierarchical limits, distributed accuracy,
observability, and resilience patterns.
"""

from .entities import RateLimitPolicy, RateLimitRequest, RateLimitResult
from .repositories import RateLimitRepository
from .services import AdvancedRateLimiter, RateLimitPolicyService
from .value_objects import RateLimitAlgorithm, RateLimitKey, RateLimitPeriod, RateLimitQuota
from .password_reset_service import RateLimitingService

__all__ = [
    "RateLimitKey",
    "RateLimitQuota",
    "RateLimitAlgorithm",
    "RateLimitPeriod",
    "RateLimitPolicy",
    "RateLimitResult",
    "RateLimitRequest",
    "AdvancedRateLimiter",
    "RateLimitPolicyService",
    "RateLimitRepository",
    "RateLimitingService",
]
