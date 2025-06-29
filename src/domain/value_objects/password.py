"""Password Value Objects for domain modeling.

These value objects encapsulate password-related business rules and validation logic,
ensuring password strength requirements are enforced consistently across the domain.
"""

import re
from dataclasses import dataclass
from typing import ClassVar

from src.utils.security import hash_password


@dataclass(frozen=True)
class Password:
    """Password value object that enforces security requirements.
    
    This value object encapsulates all password validation rules and ensures
    that only valid passwords can be created. It follows the fail-fast principle
    by validating on construction.
    
    Security Requirements:
        - Minimum 8 characters
        - Maximum 128 characters  
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        
    Attributes:
        value: The raw password string (immutable)
    """
    
    value: str
    
    # Security constraints as class constants
    MIN_LENGTH: ClassVar[int] = 8
    MAX_LENGTH: ClassVar[int] = 128
    REQUIRED_UPPERCASE: ClassVar[int] = 1
    REQUIRED_LOWERCASE: ClassVar[int] = 1
    REQUIRED_DIGITS: ClassVar[int] = 1
    REQUIRED_SPECIAL: ClassVar[int] = 1
    SPECIAL_CHARS: ClassVar[str] = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    def __post_init__(self) -> None:
        """Validate password on construction."""
        self._validate()
    
    def _validate(self) -> None:
        """Validate password against all security requirements.
        
        Raises:
            ValueError: If password doesn't meet security requirements
        """
        if not self.value:
            raise ValueError("Password cannot be empty")
        
        if len(self.value) < self.MIN_LENGTH:
            raise ValueError(f"Password must be at least {self.MIN_LENGTH} characters long")
        
        if len(self.value) > self.MAX_LENGTH:
            raise ValueError(f"Password must not exceed {self.MAX_LENGTH} characters")
        
        # Check character requirements
        if not re.search(r"[A-Z]", self.value):
            raise ValueError("Password must contain at least one uppercase letter")
        
        if not re.search(r"[a-z]", self.value):
            raise ValueError("Password must contain at least one lowercase letter")
        
        if not re.search(r"\d", self.value):
            raise ValueError("Password must contain at least one digit")
        
        if not any(char in self.SPECIAL_CHARS for char in self.value):
            raise ValueError("Password must contain at least one special character")
        
        # Check for common weak patterns
        if self._contains_weak_patterns():
            raise ValueError("Password contains common weak patterns")
    
    def _contains_weak_patterns(self) -> bool:
        """Check for common weak password patterns.
        
        Returns:
            bool: True if password contains weak patterns
        """
        weak_patterns = [
            r"(.)\1{2,}",  # Three or more consecutive identical characters
            r"123|234|345|456|567|678|789|890",  # Sequential numbers
            r"abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz",  # Sequential letters
            r"password|admin|user|login|welcome|secret",  # Common words (case-insensitive)
        ]
        
        for pattern in weak_patterns:
            if re.search(pattern, self.value.lower()):
                return True
        
        return False
    
    def to_hashed(self) -> 'HashedPassword':
        """Convert to hashed password.
        
        Returns:
            HashedPassword: Securely hashed version of this password
        """
        return HashedPassword.from_plain_password(self)


@dataclass(frozen=True)
class HashedPassword:
    """Hashed password value object.
    
    Represents a securely hashed password that can be safely stored.
    This value object ensures passwords are always properly hashed
    before storage.
    
    Attributes:
        value: The hashed password string (immutable)
    """
    
    value: str
    
    def __post_init__(self) -> None:
        """Validate hashed password format."""
        if not self.value:
            raise ValueError("Hashed password cannot be empty")
        
        # Basic validation for bcrypt hash format
        if not self.value.startswith("$2b$"):
            raise ValueError("Invalid hashed password format")
        
        if len(self.value) != 60:  # Standard bcrypt hash length
            raise ValueError("Invalid hashed password length")
    
    @classmethod
    def from_plain_password(cls, password: Password) -> 'HashedPassword':
        """Create hashed password from plain password.
        
        Args:
            password: Plain password value object
            
        Returns:
            HashedPassword: Securely hashed password
        """
        hashed_value = hash_password(password.value)
        return cls(value=hashed_value)
    
    @classmethod
    def from_hash(cls, hashed_value: str) -> 'HashedPassword':
        """Create from existing hash (e.g., from database).
        
        Args:
            hashed_value: Pre-hashed password string
            
        Returns:
            HashedPassword: Validated hashed password object
        """
        return cls(value=hashed_value) 