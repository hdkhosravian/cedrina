"""Rate Limiting Service for Password Reset operations.

This domain service handles rate limiting for password reset requests,
following single responsibility principle and clean code practices.
"""

from datetime import datetime, timezone
from typing import Optional

import structlog

from src.domain.interfaces import IRateLimitingService
from src.domain.value_objects.rate_limit import RateLimitState

logger = structlog.get_logger(__name__)


class RateLimitingService(IRateLimitingService):
    """Service for managing rate limiting in password reset operations.
    
    This service is responsible for:
    - Checking rate limit status for users
    - Recording rate limiting attempts
    - Managing rate limit windows
    - Cleaning up expired rate limits
    
    Follows single responsibility principle by focusing only on
    rate limiting concerns.
    """
    
    def __init__(self, rate_limit_state: Optional[RateLimitState] = None):
        """Initialize rate limiting service.
        
        Args:
            rate_limit_state: Optional existing state (for testing/injection)
        """
        self._state = rate_limit_state or RateLimitState()
        logger.info("RateLimitingService initialized")
    
    async def is_user_rate_limited(self, user_id: int) -> bool:
        """Check if user is currently rate limited.
        
        Args:
            user_id: User ID to check
            
        Returns:
            bool: True if user is rate limited
        """
        try:
            is_limited = self._state.is_user_limited(user_id)
            
            logger.debug(
                "Rate limit check performed",
                user_id=user_id,
                is_limited=is_limited
            )
            
            return is_limited
            
        except Exception as e:
            logger.error(
                "Error checking rate limit",
                user_id=user_id,
                error=str(e)
            )
            # Fail open for availability - don't block users due to rate limit errors
            return False
    
    async def record_attempt(self, user_id: int) -> None:
        """Record a rate limiting attempt for user.
        
        Args:
            user_id: User ID making the attempt
        """
        try:
            current_time = datetime.now(timezone.utc)
            self._state.record_attempt(user_id, current_time)
            
            logger.debug(
                "Rate limit attempt recorded",
                user_id=user_id,
                timestamp=current_time.isoformat()
            )
            
        except Exception as e:
            logger.error(
                "Error recording rate limit attempt",
                user_id=user_id,
                error=str(e)
            )
            # Don't raise - this is a supporting operation
    
    async def get_time_until_reset(self, user_id: int) -> Optional[datetime]:
        """Get time when rate limit resets for user.
        
        Args:
            user_id: User ID to check
            
        Returns:
            Optional[datetime]: Reset time if limited, None otherwise
        """
        try:
            window = self._state.get_window(user_id)
            if not window:
                return None
            
            remaining_time = window.time_until_reset()
            if not remaining_time:
                return None
            
            reset_time = datetime.now(timezone.utc) + remaining_time
            
            logger.debug(
                "Rate limit reset time calculated",
                user_id=user_id,
                reset_time=reset_time.isoformat()
            )
            
            return reset_time
            
        except Exception as e:
            logger.error(
                "Error calculating rate limit reset time",
                user_id=user_id,
                error=str(e)
            )
            return None
    
    async def cleanup_expired_windows(self) -> int:
        """Clean up expired rate limit windows.
        
        This method should be called periodically to prevent memory leaks
        and maintain good performance.
        
        Returns:
            int: Number of windows cleaned up
        """
        try:
            current_time = datetime.now(timezone.utc)
            cleaned_count = self._state.cleanup_expired_windows(current_time)
            
            logger.info(
                "Rate limit cleanup completed",
                cleaned_count=cleaned_count,
                timestamp=current_time.isoformat()
            )
            
            return cleaned_count
            
        except Exception as e:
            logger.error(
                "Error during rate limit cleanup",
                error=str(e)
            )
            return 0
    
    def get_active_windows_count(self) -> int:
        """Get count of active rate limit windows for monitoring.
        
        Returns:
            int: Number of active windows
        """
        return len(self._state._windows)
    
    def get_window_info(self, user_id: int) -> Optional[dict]:
        """Get rate limit window information for a user (for debugging).
        
        Args:
            user_id: User ID to get info for
            
        Returns:
            Optional[dict]: Window information if exists
        """
        window = self._state.get_window(user_id)
        if not window:
            return None
        
        current_time = datetime.now(timezone.utc)
        
        return {
            "user_id": window.user_id,
            "window_duration_minutes": window.window_duration.total_seconds() / 60,
            "max_attempts": window.max_attempts,
            "last_attempt_at": window.last_attempt_at.isoformat() if window.last_attempt_at else None,
            "is_limited": window.is_limit_exceeded(current_time),
            "time_until_reset": window.time_until_reset(current_time).total_seconds() if window.time_until_reset(current_time) else None,
        } 