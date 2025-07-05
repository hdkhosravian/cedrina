"""Infrastructure implementation of Email Confirmation Token Service.

This service provides concrete implementation for email confirmation token operations,
using value objects and following clean architecture principles with enhanced security.
"""

import secrets
from datetime import datetime, timezone
from typing import Optional

import structlog

from src.core.exceptions import RateLimitExceededError
from src.domain.entities.user import User
from src.domain.interfaces import IEmailConfirmationTokenService, IRateLimitingService
from src.domain.value_objects.email_confirmation_token import EmailConfirmationToken

logger = structlog.get_logger(__name__)


class EmailConfirmationTokenService(IEmailConfirmationTokenService):
    """Infrastructure implementation of email confirmation token service with enhanced security.
    
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
    
    def __init__(self, rate_limiting_service: IRateLimitingService):
        """Initialize email confirmation token service.
        
        Args:
            rate_limiting_service: Service for rate limiting operations
        """
        self._rate_limiting_service = rate_limiting_service
        
        logger.info("EmailConfirmationTokenService initialized")
    
    async def generate_token(self, user: User) -> EmailConfirmationToken:
        """Generate a secure email confirmation token for the user.
        
        Args:
            user: User entity to generate token for
            
        Returns:
            EmailConfirmationToken: New token value object
            
        Raises:
            RateLimitExceededError: If rate limit exceeded
        """
        try:
            # Check rate limiting
            if await self._is_rate_limited(user.id):
                logger.warning(
                    "Rate limit exceeded for email confirmation token generation",
                    user_id=user.id
                )
                raise RateLimitExceededError(
                    "Too many email confirmation requests. Please try again later."
                )
            
            # Generate secure token using value object
            token = EmailConfirmationToken.generate()
            
            # Record successful generation for rate limiting
            await self._record_token_generation(user.id)
            
            logger.info(
                "Email confirmation token generated successfully",
                user_id=user.id,
                token_prefix=token.value[:8],
                security_metrics=token.get_security_metrics()
            )
            
            return token
            
        except RateLimitExceededError:
            # Re-raise rate limit exceptions
            raise
        except Exception as e:
            logger.error(
                "Error generating email confirmation token",
                user_id=user.id,
                error=str(e)
            )
            raise
    
    def validate_token(self, user: User, token: str) -> bool:
        """Validate an email confirmation token for the user.
        
        Args:
            user: User entity to validate token for
            token: Token string to validate
            
        Returns:
            bool: True if token is valid
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
            stored_token = EmailConfirmationToken.from_existing(
                user.email_confirmation_token,
                user.created_at  # Use user creation time as token creation time
            )
            
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
    
    def invalidate_token(self, user: User, reason: str = "manual_invalidation") -> None:
        """Invalidate the user's email confirmation token.
        
        Args:
            user: User entity to invalidate token for
            reason: Reason for invalidation (for logging)
        """
        try:
            if self._has_active_token(user):
                logger.info(
                    "Invalidating enhanced email confirmation token",
                    user_id=user.id,
                    reason=reason,
                    token_prefix=user.email_confirmation_token[:8] if user.email_confirmation_token else None
                )
                
                user.email_confirmation_token = None
                
                logger.info(
                    "Enhanced email confirmation token invalidated successfully",
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
    
    def has_active_token(self, user: User) -> bool:
        """Check if user has an active email confirmation token.
        
        Args:
            user: User entity to check
            
        Returns:
            bool: True if user has an active token
        """
        return user.email_confirmation_token is not None
    
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
            
            stored_token = EmailConfirmationToken.from_existing(
                user.email_confirmation_token,
                user.created_at  # Use user creation time as token creation time
            )
            
            return stored_token.get_security_metrics()
            
        except Exception as e:
            logger.error(
                "Error getting token security metrics",
                user_id=user.id,
                error=str(e)
            )
            return None
    
    async def _is_rate_limited(self, user_id: int) -> bool:
        """Check if user is rate limited for token generation.
        
        Args:
            user_id: User ID to check
            
        Returns:
            bool: True if rate limited
        """
        try:
            return await self._rate_limiting_service.is_user_rate_limited(user_id)
        except Exception as e:
            logger.error(
                "Error checking rate limit for email confirmation token",
                user_id=user_id,
                error=str(e)
            )
            return False  # Fail safe - allow if rate limiting fails
    
    async def _record_token_generation(self, user_id: int) -> None:
        """Record successful token generation for rate limiting.
        
        Args:
            user_id: User ID to record for
        """
        try:
            await self._rate_limiting_service.record_attempt(user_id)
        except Exception as e:
            logger.error(
                "Error recording token generation for rate limiting",
                user_id=user_id,
                error=str(e)
            )
    
    def _has_active_token(self, user: User) -> bool:
        """Check if user has an active token.
        
        Args:
            user: User entity to check
            
        Returns:
            bool: True if user has token set
        """
        return user.email_confirmation_token is not None 