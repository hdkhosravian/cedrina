"""Email rate limiter for preventing email abuse.

This module provides rate limiting functionality specifically for email operations
to prevent abuse and ensure fair usage. It supports different rate limits for
different types of emails and provides comprehensive monitoring.

Security Features:
- Per-user rate limiting to prevent individual abuse
- Per-email-type rate limiting for targeted protection
- Sliding window rate limiting for accurate tracking
- Redis-based storage for distributed systems
- Configurable limits for different environments
"""

import time
from typing import Optional
from datetime import datetime, timezone

import structlog
from redis.asyncio import Redis

from src.core.config.settings import settings
from src.infrastructure.redis import get_redis

logger = structlog.get_logger(__name__)


class EmailRateLimiter:
    """Production-grade email rate limiter with Redis backend.
    
    This rate limiter provides comprehensive protection against email abuse
    by implementing sliding window rate limiting with configurable limits
    for different email types.
    
    Rate Limits:
    - Password Reset: 3 emails per hour per user
    - Email Confirmation: 5 emails per hour per user
    - Welcome Email: 1 email per day per user
    - Notifications: 10 emails per hour per user
    
    Features:
    - Sliding window rate limiting for accuracy
    - Redis-based storage for scalability
    - Configurable limits per email type
    - Comprehensive logging and monitoring
    - Automatic cleanup of expired entries
    """
    
    def __init__(self):
        """Initialize the email rate limiter."""
        self.redis: Optional[Redis] = None
        self._rate_limits = {
            'password_reset': 3,      # 3 emails per hour
            'email_confirmation': 5,  # 5 emails per hour
            'welcome': 1,             # 1 email per day
            'notification': 10,       # 10 emails per hour
        }
        self._window_sizes = {
            'password_reset': 3600,      # 1 hour in seconds
            'email_confirmation': 3600,  # 1 hour in seconds
            'welcome': 86400,            # 1 day in seconds
            'notification': 3600,        # 1 hour in seconds
        }
        
        logger.info(
            "EmailRateLimiter initialized",
            rate_limits=self._rate_limits,
            window_sizes=self._window_sizes
        )
    
    async def _get_redis(self) -> Redis:
        """Get Redis client with lazy initialization.
        
        Returns:
            Redis: Redis client instance
        """
        if self.redis is None:
            self.redis = await get_redis()
        return self.redis
    
    async def is_rate_limited(self, user_id: int, email_type: str) -> bool:
        """Check if user is rate limited for specific email type.
        
        Args:
            user_id: User ID to check rate limit for
            email_type: Type of email (e.g., 'password_reset', 'confirmation')
            
        Returns:
            bool: True if user is rate limited
        """
        try:
            redis = await self._get_redis()
            
            # Get rate limit configuration
            limit = self._rate_limits.get(email_type, 5)  # Default to 5 per hour
            window_size = self._window_sizes.get(email_type, 3600)  # Default to 1 hour
            
            # Generate Redis key
            key = f"email_rate_limit:{email_type}:{user_id}"
            current_time = int(time.time())
            
            # Remove expired entries (older than window_size)
            cutoff_time = current_time - window_size
            await redis.zremrangebyscore(key, 0, cutoff_time)
            
            # Count current entries
            current_count = await redis.zcard(key)
            
            # Check if rate limited
            is_limited = current_count >= limit
            
            if is_limited:
                logger.warning(
                    "Email rate limit exceeded",
                    user_id=user_id,
                    email_type=email_type,
                    current_count=current_count,
                    limit=limit,
                    window_size=window_size
                )
            else:
                logger.debug(
                    "Email rate limit check passed",
                    user_id=user_id,
                    email_type=email_type,
                    current_count=current_count,
                    limit=limit
                )
            
            return is_limited
            
        except Exception as e:
            logger.error(
                "Error checking email rate limit",
                user_id=user_id,
                email_type=email_type,
                error=str(e)
            )
            # In case of Redis failure, allow the email to prevent service disruption
            return False
    
    async def record_attempt(self, user_id: int, email_type: str) -> None:
        """Record email sending attempt for rate limiting.
        
        Args:
            user_id: User ID to record attempt for
            email_type: Type of email sent
        """
        try:
            redis = await self._get_redis()
            
            # Get window size for this email type
            window_size = self._window_sizes.get(email_type, 3600)
            
            # Generate Redis key
            key = f"email_rate_limit:{email_type}:{user_id}"
            current_time = int(time.time())
            
            # Add current timestamp to sorted set
            await redis.zadd(key, {str(current_time): current_time})
            
            # Set expiration on the key to prevent memory leaks
            await redis.expire(key, window_size)
            
            logger.debug(
                "Email attempt recorded",
                user_id=user_id,
                email_type=email_type,
                timestamp=current_time
            )
            
        except Exception as e:
            logger.error(
                "Error recording email attempt",
                user_id=user_id,
                email_type=email_type,
                error=str(e)
            )
    
    async def get_remaining_attempts(self, user_id: int, email_type: str) -> int:
        """Get remaining email attempts for user.
        
        Args:
            user_id: User ID to check
            email_type: Type of email
            
        Returns:
            int: Number of remaining attempts
        """
        try:
            redis = await self._get_redis()
            
            # Get rate limit configuration
            limit = self._rate_limits.get(email_type, 5)
            window_size = self._window_sizes.get(email_type, 3600)
            
            # Generate Redis key
            key = f"email_rate_limit:{email_type}:{user_id}"
            current_time = int(time.time())
            
            # Remove expired entries
            cutoff_time = current_time - window_size
            await redis.zremrangebyscore(key, 0, cutoff_time)
            
            # Count current entries
            current_count = await redis.zcard(key)
            
            # Calculate remaining attempts
            remaining = max(0, limit - current_count)
            
            logger.debug(
                "Email attempts remaining",
                user_id=user_id,
                email_type=email_type,
                current_count=current_count,
                limit=limit,
                remaining=remaining
            )
            
            return remaining
            
        except Exception as e:
            logger.error(
                "Error getting remaining email attempts",
                user_id=user_id,
                email_type=email_type,
                error=str(e)
            )
            # Return default limit in case of error
            return self._rate_limits.get(email_type, 5)
    
    async def reset_rate_limit(self, user_id: int, email_type: str) -> None:
        """Reset rate limit for user (admin function).
        
        Args:
            user_id: User ID to reset rate limit for
            email_type: Type of email to reset
        """
        try:
            redis = await self._get_redis()
            
            # Generate Redis key
            key = f"email_rate_limit:{email_type}:{user_id}"
            
            # Delete the key
            await redis.delete(key)
            
            logger.info(
                "Email rate limit reset",
                user_id=user_id,
                email_type=email_type
            )
            
        except Exception as e:
            logger.error(
                "Error resetting email rate limit",
                user_id=user_id,
                email_type=email_type,
                error=str(e)
            )
    
    async def get_rate_limit_status(self, user_id: int, email_type: str) -> dict:
        """Get detailed rate limit status for user.
        
        Args:
            user_id: User ID to check
            email_type: Type of email
            
        Returns:
            dict: Rate limit status information
        """
        try:
            redis = await self._get_redis()
            
            # Get rate limit configuration
            limit = self._rate_limits.get(email_type, 5)
            window_size = self._window_sizes.get(email_type, 3600)
            
            # Generate Redis key
            key = f"email_rate_limit:{email_type}:{user_id}"
            current_time = int(time.time())
            
            # Remove expired entries
            cutoff_time = current_time - window_size
            await redis.zremrangebyscore(key, 0, cutoff_time)
            
            # Count current entries
            current_count = await redis.zcard(key)
            
            # Calculate remaining attempts
            remaining = max(0, limit - current_count)
            
            # Get next reset time
            if current_count > 0:
                # Get oldest entry to calculate reset time
                oldest_entry = await redis.zrange(key, 0, 0, withscores=True)
                if oldest_entry:
                    oldest_time = int(oldest_entry[0][1])
                    next_reset = oldest_time + window_size
                else:
                    next_reset = current_time
            else:
                next_reset = current_time
            
            status = {
                'user_id': user_id,
                'email_type': email_type,
                'current_count': current_count,
                'limit': limit,
                'remaining': remaining,
                'is_rate_limited': current_count >= limit,
                'window_size_seconds': window_size,
                'next_reset_time': next_reset,
                'next_reset_iso': datetime.fromtimestamp(next_reset, tz=timezone.utc).isoformat()
            }
            
            return status
            
        except Exception as e:
            logger.error(
                "Error getting rate limit status",
                user_id=user_id,
                email_type=email_type,
                error=str(e)
            )
            return {
                'user_id': user_id,
                'email_type': email_type,
                'error': str(e),
                'is_rate_limited': False
            }
    
    def get_rate_limit_config(self) -> dict:
        """Get current rate limit configuration.
        
        Returns:
            dict: Rate limit configuration
        """
        return {
            'rate_limits': self._rate_limits.copy(),
            'window_sizes': self._window_sizes.copy()
        }
    
    async def cleanup_expired_entries(self) -> int:
        """Clean up expired rate limit entries.
        
        Returns:
            int: Number of keys cleaned up
        """
        try:
            redis = await self._get_redis()
            current_time = int(time.time())
            cleaned_count = 0
            
            # Clean up each email type
            for email_type in self._rate_limits.keys():
                pattern = f"email_rate_limit:{email_type}:*"
                keys = await redis.keys(pattern)
                
                for key in keys:
                    window_size = self._window_sizes.get(email_type, 3600)
                    cutoff_time = current_time - window_size
                    
                    # Remove expired entries
                    removed = await redis.zremrangebyscore(key, 0, cutoff_time)
                    
                    # If key is empty, delete it
                    if await redis.zcard(key) == 0:
                        await redis.delete(key)
                        cleaned_count += 1
            
            logger.info(
                "Email rate limit cleanup completed",
                cleaned_count=cleaned_count
            )
            
            return cleaned_count
            
        except Exception as e:
            logger.error(
                "Error during email rate limit cleanup",
                error=str(e)
            )
            return 0 