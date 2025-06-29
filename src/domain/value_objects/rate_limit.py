"""Rate Limiting Value Objects for domain modeling.

These value objects encapsulate rate limiting business rules and provide
a clean abstraction for rate limiting operations.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import ClassVar, Dict, Optional


@dataclass(frozen=True)
class RateLimitWindow:
    """Rate limiting window value object.
    
    Encapsulates rate limiting rules for password reset requests,
    preventing abuse while maintaining good user experience.
    
    Attributes:
        window_duration: Duration of the rate limit window
        max_attempts: Maximum attempts allowed in window
        user_id: User ID this window applies to
        last_attempt_at: Timestamp of last attempt
    """
    
    window_duration: timedelta
    max_attempts: int
    user_id: int
    last_attempt_at: Optional[datetime] = None
    
    # Default rate limiting configuration
    DEFAULT_WINDOW_MINUTES: ClassVar[int] = 5
    DEFAULT_MAX_ATTEMPTS: ClassVar[int] = 1
    
    def __post_init__(self) -> None:
        """Validate rate limit configuration."""
        if self.window_duration.total_seconds() <= 0:
            raise ValueError("Rate limit window duration must be positive")
        
        if self.max_attempts <= 0:
            raise ValueError("Max attempts must be positive")
        
        if self.user_id <= 0:
            raise ValueError("User ID must be positive")
        
        if self.last_attempt_at and not self.last_attempt_at.tzinfo:
            raise ValueError("Last attempt timestamp must be timezone-aware")
    
    @classmethod
    def create_default(cls, user_id: int) -> 'RateLimitWindow':
        """Create rate limit window with default settings.
        
        Args:
            user_id: User ID to create window for
            
        Returns:
            RateLimitWindow: New rate limit window with defaults
        """
        return cls(
            window_duration=timedelta(minutes=cls.DEFAULT_WINDOW_MINUTES),
            max_attempts=cls.DEFAULT_MAX_ATTEMPTS,
            user_id=user_id
        )
    
    @classmethod
    def create_custom(
        cls, 
        user_id: int, 
        window_minutes: int, 
        max_attempts: int
    ) -> 'RateLimitWindow':
        """Create rate limit window with custom settings.
        
        Args:
            user_id: User ID to create window for
            window_minutes: Window duration in minutes
            max_attempts: Maximum attempts allowed
            
        Returns:
            RateLimitWindow: New rate limit window with custom settings
        """
        return cls(
            window_duration=timedelta(minutes=window_minutes),
            max_attempts=max_attempts,
            user_id=user_id
        )
    
    def is_limit_exceeded(self, current_time: datetime = None) -> bool:
        """Check if rate limit is currently exceeded.
        
        Args:
            current_time: Time to check against (default: now)
            
        Returns:
            bool: True if rate limit is exceeded
        """
        if not self.last_attempt_at:
            return False  # No previous attempts
        
        check_time = current_time or datetime.now(timezone.utc)
        time_since_last = check_time - self.last_attempt_at
        
        # Rate limit exceeded if within window and max attempts reached
        return time_since_last < self.window_duration
    
    def record_attempt(self, attempt_time: datetime = None) -> 'RateLimitWindow':
        """Record a new attempt and return updated window.
        
        Args:
            attempt_time: Time of attempt (default: now)
            
        Returns:
            RateLimitWindow: New instance with updated attempt time
        """
        record_time = attempt_time or datetime.now(timezone.utc)
        
        return RateLimitWindow(
            window_duration=self.window_duration,
            max_attempts=self.max_attempts,
            user_id=self.user_id,
            last_attempt_at=record_time
        )
    
    def time_until_reset(self, current_time: datetime = None) -> Optional[timedelta]:
        """Get time remaining until rate limit resets.
        
        Args:
            current_time: Time to check against (default: now)
            
        Returns:
            Optional[timedelta]: Time until reset, None if not limited
        """
        if not self.is_limit_exceeded(current_time):
            return None
        
        check_time = current_time or datetime.now(timezone.utc)
        reset_time = self.last_attempt_at + self.window_duration
        
        remaining = reset_time - check_time
        return remaining if remaining.total_seconds() > 0 else None


@dataclass
class RateLimitState:
    """Mutable state holder for rate limiting across users.
    
    This is a mutable container that manages rate limit windows
    for multiple users. It's separate from the immutable value objects
    to handle the stateful nature of rate limiting.
    """
    
    _windows: Dict[int, RateLimitWindow]
    
    def __init__(self):
        """Initialize empty rate limit state."""
        self._windows = {}
    
    def get_window(self, user_id: int) -> Optional[RateLimitWindow]:
        """Get rate limit window for user.
        
        Args:
            user_id: User ID to get window for
            
        Returns:
            Optional[RateLimitWindow]: Window if exists, None otherwise
        """
        return self._windows.get(user_id)
    
    def set_window(self, window: RateLimitWindow) -> None:
        """Set rate limit window for user.
        
        Args:
            window: Rate limit window to set
        """
        self._windows[window.user_id] = window
    
    def is_user_limited(self, user_id: int, current_time: datetime = None) -> bool:
        """Check if user is currently rate limited.
        
        Args:
            user_id: User ID to check
            current_time: Time to check against (default: now)
            
        Returns:
            bool: True if user is rate limited
        """
        window = self.get_window(user_id)
        return window.is_limit_exceeded(current_time) if window else False
    
    def record_attempt(self, user_id: int, attempt_time: datetime = None) -> None:
        """Record attempt for user.
        
        Args:
            user_id: User ID making attempt
            attempt_time: Time of attempt (default: now)
        """
        existing_window = self.get_window(user_id)
        
        if existing_window:
            updated_window = existing_window.record_attempt(attempt_time)
        else:
            updated_window = RateLimitWindow.create_default(user_id).record_attempt(attempt_time)
        
        self.set_window(updated_window)
    
    def cleanup_expired_windows(self, current_time: datetime = None) -> int:
        """Clean up expired rate limit windows.
        
        Args:
            current_time: Time to check against (default: now)
            
        Returns:
            int: Number of windows cleaned up
        """
        check_time = current_time or datetime.now(timezone.utc)
        expired_users = []
        
        for user_id, window in self._windows.items():
            if not window.is_limit_exceeded(check_time):
                expired_users.append(user_id)
        
        for user_id in expired_users:
            del self._windows[user_id]
        
        return len(expired_users) 