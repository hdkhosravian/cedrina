"""
Rate Limiting Value Objects

Immutable value objects representing core concepts in the rate limiting domain.
These objects encapsulate business rules and invariants while providing
type safety and rich behavior.

Value Objects:
- RateLimitKey: Unique identification for rate limiting contexts
- RateLimitQuota: Configuration of limits and allowances
- RateLimitAlgorithm: Enumeration of supported algorithms
- RateLimitWindow: Time window specifications

Design Principles:
- Immutability: All value objects are immutable after creation
- Validation: Business rules enforced at construction time
- Rich Behavior: Methods that express domain concepts
- Equality: Value-based equality for proper hashing and comparison
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import hashlib
import time
from datetime import datetime, timedelta


class RateLimitAlgorithm(Enum):
    """
    Enumeration of supported rate limiting algorithms.
    
    Each algorithm has different characteristics suitable for different use cases:
    - TOKEN_BUCKET: Allows bursts but maintains long-term rate, good for API calls
    - SLIDING_WINDOW: Precise timing without burst issues, good for critical operations
    - FIXED_WINDOW: High performance but allows bursts at window boundaries
    """
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    
    @property
    def supports_burst(self) -> bool:
        """Check if algorithm supports burst allowances"""
        return self in (self.TOKEN_BUCKET, self.FIXED_WINDOW)
    
    @property
    def precision_level(self) -> str:
        """Get precision characteristics of the algorithm"""
        precision_map = {
            self.TOKEN_BUCKET: "high_burst_friendly",
            self.SLIDING_WINDOW: "highest_precision",
            self.FIXED_WINDOW: "high_performance"
        }
        return precision_map[self]


@dataclass(frozen=True, slots=True)
class RateLimitKey:
    """
    Immutable value object representing a unique rate limiting context.
    
    Combines multiple dimensions (user, endpoint, IP, tier) to create
    hierarchical and context-aware rate limiting keys. Provides security
    through hashing to prevent key manipulation attacks.
    
    Business Rules:
    - Keys must be deterministic for the same inputs
    - Keys should be resistant to manipulation
    - Keys support hierarchical organization
    - Keys are efficiently hashable for caching
    """
    user_id: Optional[str] = None
    endpoint: Optional[str] = None
    client_ip: Optional[str] = None
    user_tier: Optional[str] = None
    custom_context: Optional[str] = None
    
    # Security salt to prevent key prediction
    _security_salt: str = field(default="cedrina_rate_limit_v1", init=False)
    
    def __post_init__(self):
        """Validate key components at construction time"""
        if not any([self.user_id, self.endpoint, self.client_ip]):
            raise ValueError("At least one key component must be provided")
        
        # Validate IP format if provided
        if self.client_ip:
            self._validate_ip_format(self.client_ip)
    
    @staticmethod
    def _validate_ip_format(ip: str) -> None:
        """Validate IP address format for security"""
        if not ip or ip in ("unknown", "localhost", "127.0.0.1"):
            return  # Allow common fallback values
        
        # Basic IP validation (IPv4/IPv6 would need more sophisticated validation)
        parts = ip.split('.')
        if len(parts) == 4:
            try:
                # Fix: Check the result of all() and raise ValueError if validation fails
                if not all(0 <= int(part) <= 255 for part in parts):
                    raise ValueError(f"Invalid IP format: {ip}")
            except ValueError as e:
                # Re-raise ValueError with our custom message if int() conversion failed
                if "Invalid IP format" in str(e):
                    raise  # Re-raise our custom error
                else:
                    raise ValueError(f"Invalid IP format: {ip}")
        else:
            # IPv4 must have exactly 4 octets
            raise ValueError(f"Invalid IP format: {ip}")
    
    @property
    def composite_key(self) -> str:
        """
        Generate a composite key string combining all components.
        
        Format: component1:component2:component3:hash
        The hash provides security against key manipulation while
        maintaining deterministic behavior.
        """
        components = [
            self.user_id or "anonymous",
            self.endpoint or "global", 
            self.client_ip or "unknown",
            self.user_tier or "default",
            self.custom_context or ""
        ]
        
        base_key = ":".join(components)
        
        # Add security hash to prevent manipulation
        security_hash = hashlib.sha256(
            f"{base_key}:{self._security_salt}".encode()
        ).hexdigest()[:8]
        
        return f"{base_key}:{security_hash}"
    
    @property
    def hierarchical_keys(self) -> list[str]:
        """
        Generate hierarchical keys for multi-level rate limiting.
        
        Returns keys from most specific to most general:
        1. Full context key (user + endpoint + IP + tier)
        2. User + endpoint key
        3. User key
        4. Endpoint key  
        5. Global key
        
        This enables hierarchical rate limiting where multiple limits
        can be enforced simultaneously.
        """
        keys = []
        
        # Most specific: full context
        keys.append(self.composite_key)
        
        # User + endpoint
        if self.user_id and self.endpoint:
            user_endpoint_key = RateLimitKey(
                user_id=self.user_id,
                endpoint=self.endpoint
            )
            keys.append(user_endpoint_key.composite_key)
        
        # User-specific
        if self.user_id:
            user_key = RateLimitKey(user_id=self.user_id)
            keys.append(user_key.composite_key)
        
        # Endpoint-specific
        if self.endpoint:
            endpoint_key = RateLimitKey(endpoint=self.endpoint)
            keys.append(endpoint_key.composite_key)
        
        # Global fallback
        global_key = RateLimitKey(custom_context="global")
        keys.append(global_key.composite_key)
        
        return keys
    
    def for_user_tier(self, tier: str) -> RateLimitKey:
        """Create a new key with updated user tier"""
        return RateLimitKey(
            user_id=self.user_id,
            endpoint=self.endpoint,
            client_ip=self.client_ip,
            user_tier=tier,
            custom_context=self.custom_context
        )
    
    def for_endpoint(self, endpoint: str) -> RateLimitKey:
        """Create a new key with updated endpoint"""
        return RateLimitKey(
            user_id=self.user_id,
            endpoint=endpoint,
            client_ip=self.client_ip,
            user_tier=self.user_tier,
            custom_context=self.custom_context
        )


@dataclass(frozen=True, slots=True)
class RateLimitQuota:
    """
    Immutable value object representing rate limiting quotas and allowances.
    
    Encapsulates the business rules around request limits, time windows,
    and burst allowances. Provides methods to calculate effective limits
    and validate configurations.
    
    Business Rules:
    - Maximum requests must be positive
    - Window duration must be positive
    - Burst allowance cannot be negative
    - Effective limit includes burst allowance
    """
    max_requests: int
    window_seconds: int
    burst_allowance: int = 0
    
    def __post_init__(self):
        """Validate quota configuration at construction time"""
        if self.max_requests <= 0:
            raise ValueError("max_requests must be positive")
        
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        
        if self.burst_allowance < 0:
            raise ValueError("burst_allowance cannot be negative")
    
    @property
    def effective_limit(self) -> int:
        """
        Calculate the effective limit including burst allowance.
        
        This represents the maximum number of requests that can be made
        in a burst scenario while still respecting the long-term rate.
        """
        return self.max_requests + self.burst_allowance
    
    @property
    def requests_per_second(self) -> float:
        """Calculate the steady-state requests per second rate"""
        return self.max_requests / self.window_seconds
    
    @property
    def window_timedelta(self) -> timedelta:
        """Get the time window as a timedelta object"""
        return timedelta(seconds=self.window_seconds)
    
    def is_more_restrictive_than(self, other: RateLimitQuota) -> bool:
        """
        Compare restrictiveness with another quota.
        
        A quota is more restrictive if it allows fewer requests per second
        or has a smaller effective limit.
        """
        return (self.requests_per_second < other.requests_per_second or
                self.effective_limit < other.effective_limit)
    
    def scale_for_duration(self, duration_seconds: int) -> RateLimitQuota:
        """
        Scale the quota for a different time duration.
        
        Useful for creating sub-window quotas or extending quotas
        while maintaining the same rate.
        """
        if duration_seconds <= 0:
            raise ValueError("Duration must be positive")
        
        scaling_factor = duration_seconds / self.window_seconds
        scaled_requests = int(self.max_requests * scaling_factor)
        scaled_burst = int(self.burst_allowance * scaling_factor)
        
        return RateLimitQuota(
            max_requests=max(1, scaled_requests),  # Ensure at least 1 request
            window_seconds=duration_seconds,
            burst_allowance=scaled_burst
        )
    
    @classmethod
    def from_rate_string(cls, rate_string: str, burst_allowance: int = 0) -> RateLimitQuota:
        """
        Create quota from rate string format (e.g., "100/minute").
        
        Supported time units: second, minute, hour, day
        """
        try:
            count_str, period = rate_string.split('/')
            count = int(count_str)
            
            period_map = {
                'second': 1,
                'minute': 60,
                'hour': 3600,
                'day': 86400
            }
            
            if period not in period_map:
                raise ValueError(f"Unsupported period: {period}")
            
            window_seconds = period_map[period]
            
            return cls(
                max_requests=count,
                window_seconds=window_seconds,
                burst_allowance=burst_allowance
            )
            
        except (ValueError, AttributeError) as e:
            raise ValueError(f"Invalid rate string format: {rate_string}") from e


@dataclass(frozen=True, slots=True)
class RateLimitPeriod:
    """
    Value object representing a time period for rate limiting.
    
    Simple immutable representation of time periods used in rate limiting
    configurations and calculations.
    """
    seconds: int
    
    def __post_init__(self):
        """Validate period configuration"""
        if self.seconds < 0:
            raise ValueError("Period seconds must be non-negative")
    
    @property
    def minutes(self) -> float:
        """Get period in minutes"""
        return self.seconds / 60
    
    @property
    def hours(self) -> float:
        """Get period in hours"""
        return self.seconds / 3600
    
    @property
    def timedelta(self) -> timedelta:
        """Get period as timedelta"""
        return timedelta(seconds=self.seconds)
    
    def __str__(self) -> str:
        """String representation"""
        if self.seconds < 60:
            return f"{self.seconds}s"
        elif self.seconds < 3600:
            return f"{self.minutes:.1f}m"
        else:
            return f"{self.hours:.1f}h"


@dataclass(frozen=True, slots=True)
class RateLimitWindow:
    """
    Value object representing a time window for rate limiting calculations.
    
    Provides utilities for window-based calculations, alignment,
    and time-based operations commonly needed in rate limiting algorithms.
    """
    start_time: datetime
    duration_seconds: int
    
    def __post_init__(self):
        """Validate window configuration"""
        if self.duration_seconds <= 0:
            raise ValueError("Window duration must be positive")
    
    @property
    def end_time(self) -> datetime:
        """Calculate the end time of the window"""
        return self.start_time + timedelta(seconds=self.duration_seconds)
    
    @property
    def is_current(self) -> bool:
        """Check if the window contains the current time"""
        now = datetime.now()
        return self.start_time <= now <= self.end_time
    
    @property
    def is_expired(self) -> bool:
        """Check if the window has expired"""
        return datetime.now() > self.end_time
    
    @property
    def remaining_seconds(self) -> int:
        """Calculate remaining seconds in the window"""
        if self.is_expired:
            return 0
        
        remaining = (self.end_time - datetime.now()).total_seconds()
        return max(0, int(remaining))
    
    def contains_time(self, timestamp: datetime) -> bool:
        """Check if a timestamp falls within this window"""
        return self.start_time <= timestamp <= self.end_time
    
    @classmethod
    def current_window(cls, duration_seconds: int) -> RateLimitWindow:
        """Create a window starting at the current time"""
        return cls(
            start_time=datetime.now(),
            duration_seconds=duration_seconds
        )
    
    @classmethod
    def aligned_window(cls, duration_seconds: int, alignment_seconds: int = None) -> RateLimitWindow:
        """
        Create a window aligned to time boundaries.
        
        Useful for fixed-window algorithms where windows should align
        to specific time boundaries (e.g., minute boundaries).
        """
        if alignment_seconds is None:
            alignment_seconds = duration_seconds
        
        now = datetime.now()
        timestamp = int(now.timestamp())
        
        # Align to boundary
        aligned_timestamp = (timestamp // alignment_seconds) * alignment_seconds
        aligned_time = datetime.fromtimestamp(aligned_timestamp)
        
        return cls(
            start_time=aligned_time,
            duration_seconds=duration_seconds
        ) 