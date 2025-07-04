"""Password Value Objects for domain modeling.

These value objects encapsulate password-related business rules and validation logic,
ensuring password strength requirements are enforced consistently across the domain.
"""

import re
from dataclasses import dataclass
from typing import ClassVar, Optional

from src.utils.security import hash_password, verify_password


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
    
    def verify_against_hash(self, hashed_password: str) -> bool:
        """Verify this password against a bcrypt hash using constant-time comparison.
        
        This method provides secure password verification by delegating to the
        security utility function that uses bcrypt's built-in constant-time
        comparison to prevent timing attacks.
        
        Args:
            hashed_password: The bcrypt hash to verify against
            
        Returns:
            bool: True if password matches the hash, False otherwise
            
        Security Features:
            - Constant-time comparison via bcrypt
            - Resistant to timing attacks
            - Uses same bcrypt configuration as password hashing
            - Handles bcrypt hash format validation internally
            - Returns False for any invalid hash format (no information disclosure)
            
        Example:
            >>> password = Password("SecurePass123!")
            >>> hashed = "$2b$12$..."  # From database
            >>> is_valid = password.verify_against_hash(hashed)
        """
        try:
            return verify_password(self.value, hashed_password)
        except Exception:
            # Return False for any invalid hash format or verification error
            # This prevents information disclosure through error messages
            # and ensures consistent behavior regardless of hash validity
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
    before storage and supports both legacy unencrypted and new encrypted storage.
    
    Attributes:
        value: The hashed password string (immutable)
    """
    
    value: str
    
    def __post_init__(self) -> None:
        """Validate hashed password format."""
        if not self.value:
            raise ValueError("Hashed password cannot be empty")
        
        # Support both encrypted and unencrypted bcrypt hashes for migration
        if self.is_encrypted():
            # For encrypted hashes, validate the format more thoroughly
            if not self.value.startswith("enc_v1:"):
                raise ValueError("Invalid encrypted password format")
            # Ensure there's actual data after the prefix
            if len(self.value) <= 7 or self.value == "enc_v1:":  # "enc_v1:" is 7 characters
                raise ValueError("Invalid encrypted password format")
        else:
            # For unencrypted bcrypt hashes, validate full format
            if not self.value.startswith("$2b$"):
                raise ValueError("Invalid hashed password format")
            
            if len(self.value) != 60:  # Standard bcrypt hash length
                raise ValueError("Invalid hashed password length")
    
    def is_encrypted(self) -> bool:
        """Check if this hashed password is encrypted.
        
        Returns:
            bool: True if the hash is encrypted (has enc_v1: prefix)
        """
        return self.value.startswith("enc_v1:")
    
    @classmethod
    def from_plain_password(cls, password: Password) -> 'HashedPassword':
        """Create hashed password from plain password.
        
        Args:
            password: Plain password value object
            
        Returns:
            HashedPassword: Securely hashed password (unencrypted for compatibility)
        """
        hashed_value = hash_password(password.value)
        return cls(value=hashed_value)
    
    @classmethod
    def from_hash(cls, hashed_value: str) -> 'HashedPassword':
        """Create from existing hash (e.g., from database).
        
        Args:
            hashed_value: Pre-hashed password string (encrypted or unencrypted)
            
        Returns:
            HashedPassword: Validated hashed password object
        """
        return cls(value=hashed_value)


@dataclass(frozen=True)
class EncryptedPassword:
    """Encrypted password value object for defense-in-depth security.
    
    This value object represents a password that has been both hashed (bcrypt) and 
    encrypted (AES) for storage. It provides an additional security layer beyond
    bcrypt hashing to protect against database compromise scenarios.
    
    Security Features:
        - Two-layer protection: bcrypt + AES encryption
        - Migration compatibility with legacy unencrypted hashes
        - Immutable design prevents accidental modification
        - Clear separation between encrypted and unencrypted formats
        
    Attributes:
        encrypted_value: The encrypted bcrypt hash (with enc_v1: prefix)
    """
    
    encrypted_value: str
    
    def __post_init__(self) -> None:
        """Validate encrypted password format."""
        if not self.encrypted_value:
            raise ValueError("Encrypted password cannot be empty")
        
        if not self.encrypted_value.startswith("enc_v1:"):
            raise ValueError("Invalid encrypted password format: must start with 'enc_v1:'")
    
    @classmethod
    async def from_hashed_password(
        cls, 
        hashed_password: HashedPassword, 
        encryption_service: 'IPasswordEncryptionService'
    ) -> 'EncryptedPassword':
        """Create encrypted password from hashed password.
        
        Args:
            hashed_password: Hashed password value object
            encryption_service: Service to handle encryption
            
        Returns:
            EncryptedPassword: Encrypted password for secure storage
            
        Raises:
            EncryptionError: If encryption fails
        """
        from src.domain.interfaces import IPasswordEncryptionService
        
        # If already encrypted, return as-is
        if hashed_password.is_encrypted():
            return cls(encrypted_value=hashed_password.value)
        
        # Encrypt the bcrypt hash
        encrypted_value = await encryption_service.encrypt_password_hash(hashed_password.value)
        return cls(encrypted_value=encrypted_value)
    
    async def to_bcrypt_hash(
        self, 
        encryption_service: 'IPasswordEncryptionService'
    ) -> str:
        """Decrypt to get the original bcrypt hash for verification.
        
        Args:
            encryption_service: Service to handle decryption
            
        Returns:
            str: Decrypted bcrypt hash for password verification
            
        Raises:
            DecryptionError: If decryption fails
        """
        return await encryption_service.decrypt_password_hash(self.encrypted_value)
    
    def get_storage_value(self) -> str:
        """Get the value to store in the database.
        
        Returns:
            str: Encrypted value for database storage
        """
        return self.encrypted_value
    
    def __repr__(self) -> str:
        """Return safe string representation without exposing sensitive data.
        
        Returns:
            str: Safe representation for logging/debugging
        """
        return f"EncryptedPassword(encrypted=True, format='enc_v1')" 