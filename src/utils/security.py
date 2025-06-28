"""Security utilities for password hashing and validation.

This module provides security-related utilities including password hashing
using bcrypt with the same configuration as the UserAuthenticationService.
"""

from passlib.context import CryptContext

from src.core.config.settings import BCRYPT_WORK_FACTOR

# Configure password context with same settings as UserAuthenticationService
pwd_context = CryptContext(
    schemes=["bcrypt"], 
    deprecated="auto", 
    bcrypt__rounds=BCRYPT_WORK_FACTOR
)


def hash_password(password: str) -> str:
    """Hash a password using bcrypt.
    
    Args:
        password: Plain text password to hash
        
    Returns:
        str: Bcrypt-hashed password
        
    Security:
        - Uses bcrypt with configured work factor
        - Same configuration as UserAuthenticationService
        - Suitable for production use
    """
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a password against its hash.
    
    Args:
        password: Plain text password to verify
        hashed_password: Bcrypt hash to verify against
        
    Returns:
        bool: True if password matches hash
        
    Security:
        - Uses constant-time comparison via bcrypt
        - Resistant to timing attacks
    """
    return pwd_context.verify(password, hashed_password)


def validate_password_strength(password: str, min_length: int = 8) -> bool:
    """Validate password strength requirements.
    
    Args:
        password: Password to validate
        min_length: Minimum password length (default: 8)
        
    Returns:
        bool: True if password meets strength requirements
        
    Requirements:
        - Minimum length (default 8 characters)
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
    """
    if len(password) < min_length:
        return False
    
    # Check for required character types
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    
    return all([has_upper, has_lower, has_digit, has_special]) 