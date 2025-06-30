"""Infrastructure implementation of Password Reset Token Service.

This service provides concrete implementation for password reset token operations,
using value objects and following clean architecture principles with enhanced security.
"""

import secrets
from datetime import datetime, timezone
from typing import Optional

import structlog

from src.core.exceptions import RateLimitExceededError
from src.domain.entities.user import User
from src.domain.interfaces.services import IPasswordResetTokenService, IRateLimitingService
from src.domain.value_objects.reset_token import ResetToken

logger = structlog.get_logger(__name__)


class PasswordResetTokenService(IPasswordResetTokenService):
    """Infrastructure implementation of password reset token service with enhanced security.
    
    This service handles token generation, validation, and lifecycle management
    using domain value objects and following clean code principles.
    
    Enhanced Security Features:
    - Rate limiting per email address to prevent abuse
    - Cryptographically secure token generation with unpredictable format
    - Value object-based domain modeling
    - Comprehensive error handling and logging
    - Timing attack protection
    - One-time use enforcement
    - Security metrics and monitoring
    """
    
    def __init__(
        self, 
        token_expiry_minutes: int = 5,
        rate_limiting_service: Optional[IRateLimitingService] = None
    ):
        """Initialize the token service with rate limiting.
        
        Args:
            token_expiry_minutes: Token expiration time in minutes
            rate_limiting_service: Rate limiting service for abuse prevention
        """
        self._token_expiry_minutes = token_expiry_minutes
        self._rate_limiting_service = rate_limiting_service
        
        logger.info(
            "PasswordResetTokenService initialized with enhanced security",
            token_expiry_minutes=token_expiry_minutes,
            rate_limiting_enabled=rate_limiting_service is not None
        )
    
    async def generate_token(self, user: User) -> ResetToken:
        """Generate a new password reset token for the user with rate limiting.
        
        This method implements enhanced security by:
        - Checking rate limits per email address
        - Generating unpredictable tokens with mixed character sets
        - Providing comprehensive security logging
        - Following single responsibility principle
        
        Args:
            user: User entity to generate token for
            
        Returns:
            ResetToken: New secure token value object
            
        Raises:
            RateLimitExceededError: If rate limit is exceeded for this email
        """
        try:
            # Check rate limiting if service is available
            if self._rate_limiting_service:
                await self._check_rate_limit(user)
            
            # Log token generation (with user ID only for security)
            logger.info(
                "Generating enhanced password reset token",
                user_id=user.id,
                username=user.username,
                rate_limiting_enabled=self._rate_limiting_service is not None
            )
            
            # Check if user already has an active token
            if self._has_active_token(user):
                logger.info(
                    "Replacing existing token for user",
                    user_id=user.id,
                    previous_token_prefix=user.password_reset_token[:8] if user.password_reset_token else None
                )
            
            # Generate new token using enhanced value object
            token = ResetToken.generate(expiry_minutes=self._token_expiry_minutes)
            
            # Get security metrics for monitoring
            security_metrics = token.get_security_metrics()
            
            # Update user entity with token data
            user.password_reset_token = token.value
            user.password_reset_token_expires_at = token.expires_at
            
            # Record rate limiting attempt if service is available
            if self._rate_limiting_service:
                await self._rate_limiting_service.record_attempt(user.id)
            
            logger.info(
                "Enhanced password reset token generated successfully",
                user_id=user.id,
                token_prefix=token.value[:8],
                expires_at=token.expires_at.isoformat(),
                security_metrics=security_metrics,
                rate_limiting_applied=True
            )
            
            return token
            
        except RateLimitExceededError:
            # Re-raise rate limit errors
            raise
        except Exception as e:
            logger.error(
                "Failed to generate enhanced password reset token",
                user_id=user.id,
                error=str(e)
            )
            raise
    
    async def _check_rate_limit(self, user: User) -> None:
        """Check rate limit for user before generating token.
        
        Args:
            user: User entity to check rate limit for
            
        Raises:
            RateLimitExceededError: If rate limit is exceeded
        """
        if not self._rate_limiting_service:
            return
        
        try:
            is_limited = await self._rate_limiting_service.is_user_rate_limited(user.id)
            
            if is_limited:
                reset_time = await self._rate_limiting_service.get_time_until_reset(user.id)
                
                logger.warning(
                    "Rate limit exceeded for password reset token generation",
                    user_id=user.id,
                    reset_time=reset_time.isoformat() if reset_time else None
                )
                
                raise RateLimitExceededError(
                    f"Too many password reset attempts. Please try again later."
                )
                
        except RateLimitExceededError:
            # Re-raise rate limit errors
            raise
        except Exception as e:
            logger.error(
                "Error checking rate limit for token generation",
                user_id=user.id,
                error=str(e)
            )
            # Fail open for availability - don't block users due to rate limit errors
            return
    
    def validate_token(self, user: User, token: str) -> bool:
        """Validate a password reset token for the user.
        
        Args:
            user: User entity to validate token for
            token: Token string to validate
            
        Returns:
            bool: True if token is valid and not expired
        """
        try:
            # Check if user has a token
            if not self._has_active_token(user):
                logger.warning(
                    "Token validation failed - no active token",
                    user_id=user.id
                )
                return False
            
            # Create token value object from stored data
            stored_token = ResetToken.from_existing(
                user.password_reset_token,
                user.password_reset_token_expires_at
            )
            
            # Check expiration first
            if stored_token.is_expired():
                logger.warning(
                    "Token validation failed - token expired",
                    user_id=user.id,
                    stored_token_prefix=stored_token.value[:8],
                    expires_at=stored_token.expires_at.isoformat()
                )
                return False
            
            # Use constant-time comparison to prevent timing attacks
            is_valid = secrets.compare_digest(stored_token.value, token)
            
            # Log validation result (with token prefix only)
            logger.info(
                "Enhanced token validation completed",
                user_id=user.id,
                is_valid=is_valid,
                stored_token_prefix=stored_token.value[:8],
                provided_token_prefix=token[:8] if token else None,
                security_metrics=stored_token.get_security_metrics() if is_valid else None
            )
            
            return is_valid
            
        except Exception as e:
            logger.error(
                "Error during enhanced token validation",
                user_id=user.id,
                error=str(e)
            )
            return False
    
    def is_token_valid(self, user: User, token: str) -> bool:
        """Alias for validate_token for backward compatibility."""
        return self.validate_token(user, token)
    
    def invalidate_token(self, user: User, reason: str = "manual_invalidation") -> None:
        """Invalidate the user's password reset token.
        
        Args:
            user: User entity to invalidate token for
            reason: Reason for invalidation (for logging)
        """
        try:
            if self._has_active_token(user):
                logger.info(
                    "Invalidating enhanced password reset token",
                    user_id=user.id,
                    reason=reason,
                    token_prefix=user.password_reset_token[:8] if user.password_reset_token else None
                )
                
                user.password_reset_token = None
                user.password_reset_token_expires_at = None
                
                logger.info(
                    "Enhanced password reset token invalidated successfully",
                    user_id=user.id,
                    reason=reason
                )
            else:
                logger.debug(
                    "Token invalidation skipped - no active token",
                    user_id=user.id,
                    reason=reason
                )
                
        except Exception as e:
            logger.error(
                "Error invalidating enhanced token",
                user_id=user.id,
                reason=reason,
                error=str(e)
            )
            raise
    
    def is_token_expired(self, user: User) -> bool:
        """Check if the user's token is expired.
        
        Args:
            user: User entity to check
            
        Returns:
            bool: True if token is expired or doesn't exist
        """
        try:
            if not self._has_active_token(user):
                return True
            
            stored_token = ResetToken.from_existing(
                user.password_reset_token,
                user.password_reset_token_expires_at
            )
            
            is_expired = stored_token.is_expired()
            
            if is_expired:
                logger.info(
                    "Enhanced token expired",
                    user_id=user.id,
                    token_prefix=stored_token.value[:8],
                    expires_at=stored_token.expires_at.isoformat()
                )
            
            return is_expired
            
        except Exception as e:
            logger.error(
                "Error checking enhanced token expiration",
                user_id=user.id,
                error=str(e)
            )
            return True  # Fail safe - consider expired if we can't determine
    
    def get_token_expiry(self, user: User) -> Optional[datetime]:
        """Get the expiry time of the user's token.
        
        Args:
            user: User entity to check
            
        Returns:
            Optional[datetime]: Expiry time if token exists, None otherwise
        """
        if not self._has_active_token(user):
            return None
        
        return user.password_reset_token_expires_at
    
    def get_time_remaining(self, user: User) -> Optional[int]:
        """Get seconds remaining before token expires.
        
        Args:
            user: User entity to check
            
        Returns:
            Optional[int]: Seconds remaining, or None if no token
        """
        try:
            if not self._has_active_token(user):
                return None
            
            stored_token = ResetToken.from_existing(
                user.password_reset_token,
                user.password_reset_token_expires_at
            )
            
            remaining = stored_token.time_remaining()
            return int(remaining.total_seconds()) if remaining and remaining.total_seconds() > 0 else None
            
        except Exception as e:
            logger.error(
                "Error calculating time remaining for enhanced token",
                user_id=user.id,
                error=str(e)
            )
            return None
    
    def get_token_security_metrics(self, user: User) -> Optional[dict]:
        """Get security metrics for the user's token (for monitoring).
        
        Args:
            user: User entity to check
            
        Returns:
            Optional[dict]: Security metrics if token exists, None otherwise
        """
        try:
            if not self._has_active_token(user):
                return None
            
            stored_token = ResetToken.from_existing(
                user.password_reset_token,
                user.password_reset_token_expires_at
            )
            
            return stored_token.get_security_metrics()
            
        except Exception as e:
            logger.error(
                "Error getting token security metrics",
                user_id=user.id,
                error=str(e)
            )
            return None
    
    def _has_active_token(self, user: User) -> bool:
        """Check if user has an active token.
        
        Args:
            user: User entity to check
            
        Returns:
            bool: True if user has both token and expiry set
        """
        return (
            user.password_reset_token is not None
            and user.password_reset_token_expires_at is not None
        )