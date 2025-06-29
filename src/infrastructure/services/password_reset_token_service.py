"""Infrastructure implementation of Password Reset Token Service.

This service provides concrete implementation for password reset token operations,
using value objects and following clean architecture principles.
"""

import secrets
from datetime import datetime, timezone
from typing import Optional

import structlog

from src.domain.entities.user import User
from src.domain.interfaces.services import IPasswordResetTokenService
from src.domain.value_objects.reset_token import ResetToken

logger = structlog.get_logger(__name__)


class PasswordResetTokenService(IPasswordResetTokenService):
    """Infrastructure implementation of password reset token service.
    
    This service handles token generation, validation, and lifecycle management
    using domain value objects and following clean code principles.
    
    Features:
    - Cryptographically secure token generation
    - Value object-based domain modeling
    - Comprehensive error handling and logging
    - Timing attack protection
    - One-time use enforcement
    """
    
    def __init__(self, token_expiry_minutes: int = 5):
        """Initialize the token service.
        
        Args:
            token_expiry_minutes: Token expiration time in minutes
        """
        self._token_expiry_minutes = token_expiry_minutes
        logger.info(
            "PasswordResetTokenService initialized",
            token_expiry_minutes=token_expiry_minutes
        )
    
    def generate_token(self, user: User) -> ResetToken:
        """Generate a new password reset token for the user.
        
        Args:
            user: User entity to generate token for
            
        Returns:
            ResetToken: New secure token value object
        """
        try:
            # Log token generation (with user ID only for security)
            logger.info(
                "Generating password reset token",
                user_id=user.id,
                username=user.username
            )
            
            # Check if user already has an active token
            if self._has_active_token(user):
                logger.info(
                    "Replacing existing token for user",
                    user_id=user.id,
                    previous_token_prefix=user.password_reset_token[:8] if user.password_reset_token else None
                )
            
            # Generate new token using value object
            token = ResetToken.generate(expiry_minutes=self._token_expiry_minutes)
            
            # Update user entity with token data
            user.password_reset_token = token.value
            user.password_reset_token_expires_at = token.expires_at
            
            logger.info(
                "Password reset token generated successfully",
                user_id=user.id,
                token_prefix=token.value[:8],
                expires_at=token.expires_at.isoformat()
            )
            
            return token
            
        except Exception as e:
            logger.error(
                "Failed to generate password reset token",
                user_id=user.id,
                error=str(e)
            )
            raise
    
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
                "Token validation completed",
                user_id=user.id,
                is_valid=is_valid,
                stored_token_prefix=stored_token.value[:8],
                provided_token_prefix=token[:8] if token else None
            )
            
            return is_valid
            
        except Exception as e:
            logger.error(
                "Error during token validation",
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
                    "Invalidating password reset token",
                    user_id=user.id,
                    reason=reason,
                    token_prefix=user.password_reset_token[:8] if user.password_reset_token else None
                )
                
                user.password_reset_token = None
                user.password_reset_token_expires_at = None
                
                logger.info(
                    "Password reset token invalidated successfully",
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
                "Error invalidating token",
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
                    "Token expired",
                    user_id=user.id,
                    token_prefix=stored_token.value[:8],
                    expires_at=stored_token.expires_at.isoformat()
                )
            
            return is_expired
            
        except Exception as e:
            logger.error(
                "Error checking token expiration",
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
                "Error calculating time remaining",
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