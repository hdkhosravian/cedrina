"""Reset Token Value Object for secure token management.

This value object encapsulates password reset token business rules,
ensuring tokens are always valid and properly formatted.
"""

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import ClassVar


@dataclass(frozen=True)
class ResetToken:
    """Password reset token value object with built-in validation.
    
    This value object ensures that reset tokens are always properly
    formatted and contain sufficient entropy for security.
    
    Security Features:
        - 64-character hexadecimal format (256-bit entropy)
        - Cryptographically secure generation
        - Format validation on construction
        - Immutable once created
        
    Attributes:
        value: The token string (64 hex characters)
        expires_at: Token expiration timestamp
    """
    
    value: str
    expires_at: datetime
    
    # Security constants
    TOKEN_LENGTH: ClassVar[int] = 64
    TOKEN_BYTES: ClassVar[int] = 32
    DEFAULT_EXPIRY_MINUTES: ClassVar[int] = 5
    
    def __post_init__(self) -> None:
        """Validate token format on construction."""
        self._validate_format()
        self._validate_expiry()
    
    def _validate_format(self) -> None:
        """Validate token format requirements.
        
        Raises:
            ValueError: If token format is invalid
        """
        if not self.value:
            raise ValueError("Token cannot be empty")
        
        if len(self.value) != self.TOKEN_LENGTH:
            raise ValueError(f"Token must be exactly {self.TOKEN_LENGTH} characters")
        
        # Validate hexadecimal format
        try:
            int(self.value, 16)
        except ValueError:
            raise ValueError("Token must contain only hexadecimal characters")
    
    def _validate_expiry(self) -> None:
        """Validate expiry timestamp.
        
        Raises:
            ValueError: If expiry is invalid
        """
        if not self.expires_at:
            raise ValueError("Token expiry cannot be empty")
        
        if not self.expires_at.tzinfo:
            raise ValueError("Token expiry must be timezone-aware")
    
    @classmethod
    def generate(cls, expiry_minutes: int = None) -> 'ResetToken':
        """Generate a new cryptographically secure reset token.
        
        Args:
            expiry_minutes: Token expiry time in minutes (default: 5)
            
        Returns:
            ResetToken: New secure token with expiration
        """
        # Generate cryptographically secure token
        token_value = secrets.token_hex(cls.TOKEN_BYTES)
        
        # Set expiration time
        expiry_mins = expiry_minutes or cls.DEFAULT_EXPIRY_MINUTES
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=expiry_mins)
        
        return cls(value=token_value, expires_at=expires_at)
    
    @classmethod
    def from_existing(cls, token_value: str, expires_at: datetime) -> 'ResetToken':
        """Create token from existing values (e.g., from database).
        
        Args:
            token_value: Existing token string
            expires_at: Existing expiration timestamp
            
        Returns:
            ResetToken: Validated token object
        """
        return cls(value=token_value, expires_at=expires_at)
    
    def is_expired(self, current_time: datetime = None) -> bool:
        """Check if token is expired.
        
        Args:
            current_time: Time to check against (default: now)
            
        Returns:
            bool: True if token is expired
        """
        check_time = current_time or datetime.now(timezone.utc)
        return check_time > self.expires_at
    
    def is_valid(self, current_time: datetime = None) -> bool:
        """Check if token is valid (not expired).
        
        Args:
            current_time: Time to check against (default: now)
            
        Returns:
            bool: True if token is valid
        """
        return not self.is_expired(current_time)
    
    def time_remaining(self, current_time: datetime = None) -> timedelta:
        """Get remaining time before expiration.
        
        Args:
            current_time: Time to check against (default: now)
            
        Returns:
            timedelta: Remaining time (negative if expired)
        """
        check_time = current_time or datetime.now(timezone.utc)
        return self.expires_at - check_time
    
    def mask_for_logging(self) -> str:
        """Get masked token for safe logging.
        
        Returns:
            str: Token with only first 8 characters visible
        """
        return f"{self.value[:8]}..." 