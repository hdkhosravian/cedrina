"""Email Confirmation Token Value Object.

This module defines the EmailConfirmationToken value object following
Domain-Driven Design principles. It encapsulates the business logic
for email confirmation token generation, validation, and lifecycle management.

Key DDD Principles Applied:
- Value Object: Immutable and identity-less
- Domain Logic: Encapsulates token validation rules
- Ubiquitous Language: Uses business terminology
- Fail-Safe: Implements secure token generation and validation
"""

import secrets
from datetime import datetime, timezone
from typing import Optional

import structlog

from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class EmailConfirmationToken:
    """Value object representing an email confirmation token.
    
    This value object encapsulates the business logic for email confirmation
    tokens, including secure generation, validation, and lifecycle management.
    
    Security Features:
    - Cryptographically secure token generation
    - Constant-time comparison to prevent timing attacks
    - Token format validation
    - Security metrics for monitoring
    
    DDD Principles:
    - Value Object: Immutable and identity-less
    - Domain Logic: Encapsulates token validation rules
    - Ubiquitous Language: Uses business terminology
    - Fail-Safe: Implements secure token generation and validation
    """
    
    # Token length constants (64 characters for 32 bytes)
    MIN_TOKEN_LENGTH = 64
    MAX_TOKEN_LENGTH = 64
    
    def __init__(self, value: str, created_at: Optional[datetime] = None):
        """Initialize email confirmation token.
        
        Args:
            value: Token string value
            created_at: Token creation timestamp (defaults to current time)
            
        Raises:
            ValueError: If token format is invalid
        """
        self._value = self._validate_token_format(value)
        self._created_at = created_at or datetime.now(timezone.utc)
        
        logger.debug(
            "Email confirmation token created",
            token_prefix=self._value[:8],
            created_at=self._created_at.isoformat()
        )
    
    @property
    def value(self) -> str:
        """Get token value.
        
        Returns:
            str: Token string value
        """
        return self._value
    
    @property
    def created_at(self) -> datetime:
        """Get token creation timestamp.
        
        Returns:
            datetime: Token creation timestamp
        """
        return self._created_at
    
    @classmethod
    def generate(cls) -> 'EmailConfirmationToken':
        """Generate a new secure email confirmation token.
        
        Returns:
            EmailConfirmationToken: New token instance
            
        Security Features:
            - Uses secrets module for cryptographically secure generation
            - 32-byte token provides 256-bit security
            - Hex encoding for URL-safe format
        """
        # Generate 32 bytes (256 bits) of secure random data
        token_bytes = secrets.token_bytes(32)
        token_value = token_bytes.hex()
        
        logger.info(
            "Generated new email confirmation token",
            token_prefix=token_value[:8],
            security_bits=256
        )
        
        return cls(token_value)
    
    @classmethod
    def from_existing(cls, value: str, created_at: Optional[datetime] = None) -> 'EmailConfirmationToken':
        """Create token from existing value.
        
        Args:
            value: Existing token value
            created_at: Token creation timestamp
            
        Returns:
            EmailConfirmationToken: Token instance
            
        Raises:
            ValueError: If token format is invalid
        """
        return cls(value, created_at)
    
    def _validate_token_format(self, value: str) -> str:
        """Validate token format.
        
        Args:
            value: Token value to validate
            
        Returns:
            str: Validated token value
            
        Raises:
            ValueError: If token format is invalid
        """
        if not value:
            raise ValueError(
                get_translated_message("email_confirmation_token_cannot_be_empty", "en")
            )
        
        if not isinstance(value, str):
            raise ValueError(
                get_translated_message("email_confirmation_token_must_be_string", "en")
            )
        
        # Validate hex format (64 characters for 32 bytes)
        if len(value) != 64:
            raise ValueError(
                get_translated_message("email_confirmation_token_length_invalid", "en")
            )
        
        try:
            # Validate hex format
            int(value, 16)
        except ValueError:
            raise ValueError(
                get_translated_message("email_confirmation_token_format_invalid", "en")
            )
        
        return value
    
    def __eq__(self, other: object) -> bool:
        """Compare tokens for equality using constant-time comparison.
        
        Args:
            other: Other object to compare
            
        Returns:
            bool: True if tokens are equal
            
        Security Features:
            - Uses secrets.compare_digest for constant-time comparison
            - Prevents timing attacks
        """
        if not isinstance(other, EmailConfirmationToken):
            return False
        
        return secrets.compare_digest(self._value, other._value)
    
    def __hash__(self) -> int:
        """Get hash value for token.
        
        Returns:
            int: Hash value
        """
        return hash(self._value)
    
    def __str__(self) -> str:
        """Get string representation of token.
        
        Returns:
            str: Token value (masked for security)
        """
        return f"{self._value[:8]}...{self._value[-8:]}"
    
    def __repr__(self) -> str:
        """Get string representation for debugging.
        
        Returns:
            str: Debug representation (masked for security)
        """
        return f"EmailConfirmationToken(value='{self._value[:8]}...', created_at={self._created_at.isoformat()})"
    
    def get_security_metrics(self) -> dict:
        """Get security metrics for monitoring.
        
        Returns:
            dict: Security metrics including token age and format
        """
        now = datetime.now(timezone.utc)
        age_seconds = (now - self._created_at).total_seconds()
        
        return {
            "token_length": len(self._value),
            "token_format": "hex",
            "security_bits": 256,
            "age_seconds": age_seconds,
            "created_at": self._created_at.isoformat(),
            "is_secure": len(self._value) == 64 and all(c in '0123456789abcdef' for c in self._value.lower())
        } 