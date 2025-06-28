"""Password Reset Token Service for secure token management.

This service encapsulates password reset token operations following Domain-Driven Design principles.
It provides secure token generation, validation, and cleanup operations with advanced security features.
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from src.domain.entities.user import User


class PasswordResetTokenService:
    """Service for managing password reset tokens with enterprise-grade security.
    
    This service encapsulates all password reset token operations, providing secure
    token generation, validation with timing attack protection, and proper cleanup.
    
    Security Features:
        - Cryptographically secure token generation (256-bit entropy)
        - Timing attack protection via constant-time comparison
        - Automatic token expiration
        - Token replacement on new generation
        - Secure cleanup operations
    """

    @staticmethod
    def generate_token(user: User, expire_minutes: int = 15) -> str:
        """Generate a secure password reset token with expiration.
        
        Creates a cryptographically secure token using 32 bytes of randomness
        and sets an expiration timestamp. Any existing token is replaced.
        
        Args:
            user: User entity to generate token for
            expire_minutes: Token expiration time in minutes (default: 15)
            
        Returns:
            str: Hex-encoded 64-character token
            
        Security:
            - Uses secrets.token_hex() for cryptographically secure randomness
            - 32 bytes (256 bits) provides sufficient entropy against brute force
            - Tokens automatically expire to limit attack window
            - Each new token replaces the previous one
        """
        # Generate cryptographically secure token (32 bytes = 64 hex chars)
        token = secrets.token_hex(32)
        
        # Set token and expiration on user entity
        user.password_reset_token = token
        user.password_reset_token_expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=expire_minutes
        )
        
        return token
    
    @staticmethod
    def is_token_valid(user: User, token: str) -> bool:
        """Validate a password reset token using constant-time comparison.
        
        Checks token value and expiration using timing-attack resistant comparison.
        
        Args:
            user: User entity containing the stored token
            token: Token to validate
            
        Returns:
            bool: True if token is valid and not expired, False otherwise
            
        Security:
            - Uses secrets.compare_digest() to prevent timing attacks
            - Checks expiration to prevent replay attacks
            - Returns False for any invalid state (no token, expired, mismatch)
        """
        # Check if token exists and is not expired
        if (
            not user.password_reset_token 
            or not user.password_reset_token_expires_at
            or datetime.now(timezone.utc) > user.password_reset_token_expires_at
        ):
            return False
        
        # Use constant-time comparison to prevent timing attacks
        return secrets.compare_digest(user.password_reset_token, token)
    
    @staticmethod
    def clear_token(user: User) -> None:
        """Clear password reset token and expiration.
        
        Should be called after successful password reset or when token expires.
        Ensures clean state and prevents token reuse.
        
        Args:
            user: User entity to clear token from
        
        Security:
            - Prevents token reuse after successful reset
            - Should be called in finally blocks to ensure cleanup
        """
        user.password_reset_token = None
        user.password_reset_token_expires_at = None
    
    @staticmethod
    def is_token_expired(user: User) -> bool:
        """Check if the current password reset token is expired.
        
        Args:
            user: User entity to check
            
        Returns:
            bool: True if token exists but is expired, False otherwise
        """
        if not user.password_reset_token_expires_at:
            return False
            
        return datetime.now(timezone.utc) > user.password_reset_token_expires_at
    
    @staticmethod
    def get_token_expiry(user: User) -> Optional[datetime]:
        """Get the expiration datetime of the current token.
        
        Args:
            user: User entity to get expiry for
            
        Returns:
            Optional[datetime]: Token expiry datetime or None if no token exists
        """
        return user.password_reset_token_expires_at 