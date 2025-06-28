"""Password Reset Token Service for secure token management.

This service encapsulates password reset token operations following Domain-Driven Design principles.
It provides secure token generation, validation, and cleanup operations with advanced security features.

Security Features:
- 5-minute token expiration for minimal attack window
- One-time use tokens (invalidated after successful use)
- Cryptographically secure token generation (256-bit entropy)
- Timing attack protection via constant-time comparison
- Token usage tracking and audit logging
- Automatic cleanup and invalidation
- Secure token format validation
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
import structlog

from src.domain.entities.user import User

logger = structlog.get_logger(__name__)


class PasswordResetTokenService:
    """Service for managing password reset tokens with enterprise-grade security.
    
    This service encapsulates all password reset token operations, providing secure
    token generation, validation with timing attack protection, and proper cleanup.
    
    Security Features:
        - Cryptographically secure token generation (256-bit entropy)
        - 5-minute expiration window for reduced attack surface
        - One-time use tokens (invalidated immediately after use)
        - Timing attack protection via constant-time comparison
        - Comprehensive security audit logging
        - Automatic token cleanup and rotation
        - Secure token format validation (64 hex characters)
        
    Design Principles:
        - Fail-secure: Invalid states result in denial
        - Defense in depth: Multiple validation layers
        - Least privilege: Minimal token lifetime
        - Audit trail: Comprehensive security logging
    """

    # Security constants
    TOKEN_EXPIRY_MINUTES = 5  # Minimal 5-minute window
    TOKEN_LENGTH_BYTES = 32   # 256-bit entropy
    TOKEN_LENGTH_HEX = 64     # 64 hex characters

    @staticmethod
    def generate_token(user: User, expire_minutes: int = None) -> str:
        """Generate a secure password reset token with 5-minute expiration.
        
        Creates a cryptographically secure token using 32 bytes of randomness
        and sets a 5-minute expiration timestamp. Any existing token is replaced
        to prevent token accumulation attacks.
        
        Args:
            user: User entity to generate token for
            expire_minutes: Token expiration time in minutes (defaults to 5 for security)
            
        Returns:
            str: Hex-encoded 64-character token
            
        Security Features:
            - Uses secrets.token_hex() for cryptographically secure randomness
            - 32 bytes (256 bits) provides sufficient entropy against brute force
            - 5-minute expiration minimizes attack window
            - Each new token replaces the previous one (no token accumulation)
            - Comprehensive security logging for audit trails
            
        Raises:
            ValueError: If user is None or invalid
        """
        if not user:
            logger.error("Token generation attempted with invalid user")
            raise ValueError("User cannot be None")
            
        # Use secure default of 5 minutes if not specified
        expiry_minutes = expire_minutes or PasswordResetTokenService.TOKEN_EXPIRY_MINUTES
        
        # Generate cryptographically secure token (32 bytes = 64 hex chars)
        token = secrets.token_hex(PasswordResetTokenService.TOKEN_LENGTH_BYTES)
        
        # Clear any existing token first (prevent accumulation)
        if user.password_reset_token:
            logger.info(
                "Replacing existing password reset token",
                user_id=user.id,
                username=user.username,
                previous_token_prefix=user.password_reset_token[:8]
            )
        
        # Set token and short expiration on user entity
        user.password_reset_token = token
        user.password_reset_token_expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=expiry_minutes
        )
        
        logger.info(
            "Password reset token generated",
            user_id=user.id,
            username=user.username,
            token_prefix=token[:8],
            expires_in_minutes=expiry_minutes,
            expires_at=user.password_reset_token_expires_at.isoformat()
        )
        
        return token
    
    @staticmethod
    def is_token_valid(user: User, token: str) -> bool:
        """Validate a password reset token using constant-time comparison.
        
        Performs comprehensive validation including format, expiration, and
        constant-time comparison to prevent timing attacks.
        
        Args:
            user: User entity containing the stored token
            token: Token to validate
            
        Returns:
            bool: True if token is valid and not expired, False otherwise
            
        Security Features:
            - Uses secrets.compare_digest() to prevent timing attacks
            - Validates token format to prevent injection attacks
            - Checks expiration to prevent replay attacks
            - Comprehensive logging for security monitoring
            - Fail-secure: any invalid state returns False
            
        Side Effects:
            - Logs security events for audit trails
            - Does not modify user state (read-only operation)
        """
        if not user or not token:
            logger.warning(
                "Token validation attempted with invalid parameters",
                user_provided=user is not None,
                token_provided=bool(token)
            )
            return False
            
        # Validate token format (must be exactly 64 hex characters)
        if not PasswordResetTokenService._is_valid_token_format(token):
            logger.warning(
                "Invalid token format detected",
                user_id=user.id,
                username=user.username,
                token_length=len(token) if token else 0
            )
            return False
        
        # Check if user has a token stored
        if not user.password_reset_token:
            logger.warning(
                "Token validation attempted for user with no stored token",
                user_id=user.id,
                username=user.username
            )
            return False
            
        # Check if token has expiration set
        if not user.password_reset_token_expires_at:
            logger.warning(
                "Token validation attempted for user with no expiration set",
                user_id=user.id,
                username=user.username
            )
            return False
        
        # Check expiration first (fail fast for expired tokens)
        current_time = datetime.now(timezone.utc)
        if current_time > user.password_reset_token_expires_at:
            time_expired = current_time - user.password_reset_token_expires_at
            logger.warning(
                "Expired token validation attempted",
                user_id=user.id,
                username=user.username,
                expired_by_seconds=time_expired.total_seconds(),
                token_prefix=token[:8]
            )
            return False
        
        # Use constant-time comparison to prevent timing attacks
        is_valid = secrets.compare_digest(user.password_reset_token, token)
        
        if is_valid:
            remaining_time = user.password_reset_token_expires_at - current_time
            logger.info(
                "Valid token validation successful",
                user_id=user.id,
                username=user.username,
                token_prefix=token[:8],
                remaining_seconds=remaining_time.total_seconds()
            )
        else:
            logger.warning(
                "Invalid token validation attempted",
                user_id=user.id,
                username=user.username,
                stored_token_prefix=user.password_reset_token[:8],
                provided_token_prefix=token[:8]
            )
        
        return is_valid
    
    @staticmethod
    def invalidate_token(user: User, reason: str = "used") -> None:
        """Invalidate password reset token immediately (one-time use enforcement).
        
        Clears password reset token and expiration to enforce one-time use.
        Should be called after successful password reset or when token needs
        to be invalidated for security reasons.
        
        Args:
            user: User entity to invalidate token for
            reason: Reason for invalidation (for audit logging)
        
        Security Features:
            - Enforces one-time use of tokens
            - Comprehensive audit logging
            - Immediate invalidation prevents reuse
            - Can be called multiple times safely (idempotent)
        """
        if not user:
            logger.error("Token invalidation attempted with invalid user")
            return
            
        if user.password_reset_token:
            logger.info(
                "Password reset token invalidated",
                user_id=user.id,
                username=user.username,
                token_prefix=user.password_reset_token[:8],
                reason=reason,
                invalidated_at=datetime.now(timezone.utc).isoformat()
            )
        
        user.password_reset_token = None
        user.password_reset_token_expires_at = None
    
    @staticmethod
    def clear_token(user: User) -> None:
        """Clear password reset token and expiration (alias for invalidate_token).
        
        Provided for backward compatibility. Prefer invalidate_token() for
        better audit trails.
        
        Args:
            user: User entity to clear token from
        """
        PasswordResetTokenService.invalidate_token(user, reason="cleared")
    
    @staticmethod
    def is_token_expired(user: User) -> bool:
        """Check if the current password reset token is expired.
        
        Args:
            user: User entity to check
            
        Returns:
            bool: True if token exists but is expired, False otherwise
            
        Security Features:
            - Accurate expiration checking with timezone awareness
            - Logging for security monitoring
            - Safe for users without tokens
        """
        if not user or not user.password_reset_token_expires_at:
            return False
            
        is_expired = datetime.now(timezone.utc) > user.password_reset_token_expires_at
        
        if is_expired and user.password_reset_token:
            time_expired = datetime.now(timezone.utc) - user.password_reset_token_expires_at
            logger.info(
                "Expired token detected",
                user_id=user.id,
                username=user.username,
                token_prefix=user.password_reset_token[:8],
                expired_by_seconds=time_expired.total_seconds()
            )
            
        return is_expired
    
    @staticmethod
    def get_token_expiry(user: User) -> Optional[datetime]:
        """Get the expiration datetime of the current token.
        
        Args:
            user: User entity to get expiry for
            
        Returns:
            Optional[datetime]: Token expiry datetime or None if no token exists
        """
        return user.password_reset_token_expires_at if user else None
    
    @staticmethod
    def get_remaining_time(user: User) -> Optional[timedelta]:
        """Get remaining time before token expires.
        
        Args:
            user: User entity to check
            
        Returns:
            Optional[timedelta]: Remaining time or None if no valid token
        """
        if not user or not user.password_reset_token_expires_at:
            return None
            
        remaining = user.password_reset_token_expires_at - datetime.now(timezone.utc)
        return remaining if remaining.total_seconds() > 0 else None
    
    @staticmethod
    def _is_valid_token_format(token: str) -> bool:
        """Validate token format to prevent injection attacks.
        
        Args:
            token: Token to validate
            
        Returns:
            bool: True if token has valid format (64 hex characters)
            
        Security Features:
            - Prevents injection attacks via format validation
            - Ensures consistent token format across system
            - Validates length and character set
        """
        if not token:
            return False
            
        if len(token) != PasswordResetTokenService.TOKEN_LENGTH_HEX:
            return False
            
        # Ensure all characters are valid hexadecimal
        try:
            int(token, 16)
            return True
        except ValueError:
            return False 