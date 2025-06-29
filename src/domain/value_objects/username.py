"""Username value object for domain modeling.

This value object encapsulates username business rules and validation,
providing a type-safe representation of usernames in the domain.
"""

import re
from dataclasses import dataclass
from typing import ClassVar

from structlog import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class Username:
    """Value object for username with validation and business rules.
    
    Enforces username format requirements:
    - 3-30 characters in length
    - Alphanumeric characters, underscores, hyphens only
    - Cannot start or end with underscore or hyphen
    - Case-insensitive (stored as lowercase)
    - No consecutive special characters
    
    Security features:
    - Prevents username enumeration through consistent validation
    - Blocks common attack patterns (SQL injection attempts)
    - Enforces consistent formatting across the system
    """
    
    value: str
    
    # Business rule constants
    MIN_LENGTH: ClassVar[int] = 3
    MAX_LENGTH: ClassVar[int] = 30
    VALID_PATTERN: ClassVar[str] = r'^[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$'
    
    # Security patterns to block
    BLOCKED_PATTERNS: ClassVar[list] = [
        r'.*admin.*',
        r'.*root.*', 
        r'.*system.*',
        r'.*null.*',
        r'.*undefined.*',
        r'.*script.*',
        r'.*select.*',
        r'.*drop.*',
        r'.*union.*',
    ]
    
    def __post_init__(self):
        """Validate username after initialization."""
        if not self.value:
            raise ValueError("Username cannot be empty")
        
        # Convert to lowercase for consistency
        normalized_value = self.value.strip().lower()
        object.__setattr__(self, 'value', normalized_value)
        
        # Length validation
        if len(normalized_value) < self.MIN_LENGTH:
            raise ValueError(f"Username must be at least {self.MIN_LENGTH} characters long")
        
        if len(normalized_value) > self.MAX_LENGTH:
            raise ValueError(f"Username must be no more than {self.MAX_LENGTH} characters long")
        
        # Format validation
        if not re.match(self.VALID_PATTERN, normalized_value):
            raise ValueError(
                "Username must contain only alphanumeric characters, underscores, "
                "and hyphens, and cannot start or end with special characters"
            )
        
        # Security validation
        for pattern in self.BLOCKED_PATTERNS:
            if re.search(pattern, normalized_value, re.IGNORECASE):
                raise ValueError("Username contains blocked content")
        
        # No consecutive special characters
        if re.search(r'[_-]{2,}', normalized_value):
            raise ValueError("Username cannot contain consecutive underscores or hyphens")
        
        logger.debug("Username validated successfully", username=self.mask_for_logging())
    
    def mask_for_logging(self) -> str:
        """Return masked username for safe logging.
        
        Returns:
            str: Masked username (first 2 chars + asterisks)
        """
        if len(self.value) <= 2:
            return "*" * len(self.value)
        return self.value[:2] + "*" * (len(self.value) - 2)
    
    def is_system_username(self) -> bool:
        """Check if this is a system/reserved username.
        
        Returns:
            bool: True if username is reserved for system use
        """
        system_usernames = {
            'admin', 'administrator', 'root', 'system', 'user',
            'guest', 'public', 'anonymous', 'test', 'demo'
        }
        return self.value in system_usernames
    
    @classmethod
    def create_safe(cls, value: str) -> 'Username':
        """Create username with additional safety checks.
        
        Args:
            value: Raw username string
            
        Returns:
            Username: Validated username object
            
        Raises:
            ValueError: If username fails validation or safety checks
        """
        username = cls(value)
        
        if username.is_system_username():
            raise ValueError("Username is reserved for system use")
        
        return username
    
    def __str__(self) -> str:
        """String representation."""
        return self.value
    
    def __eq__(self, other) -> bool:
        """Equality comparison."""
        if isinstance(other, Username):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other.lower()
        return False
    
    def __hash__(self) -> int:
        """Hash for use in sets and dictionaries."""
        return hash(self.value) 