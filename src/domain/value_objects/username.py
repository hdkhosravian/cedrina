"""Username value object for domain modeling with enhanced security validation.

This value object encapsulates username business rules and validation,
providing a type-safe representation of usernames in the domain with
comprehensive security controls.

SECURITY NOTE: This class now delegates to SecureUsername for enhanced
security validation. The original Username class is maintained for
backward compatibility but should be migrated to SecureUsername.
"""

import re
from dataclasses import dataclass
from typing import ClassVar

from structlog import get_logger

# Import new secure validation components
from src.domain.validation.secure_username import SecureUsername, UsernameValidationError

logger = get_logger(__name__)


@dataclass(frozen=True)
class Username:
    """Legacy username value object - DEPRECATED in favor of SecureUsername.
    
    This class maintains backward compatibility while delegating security-critical
    validation to the new SecureUsername implementation. New code should use
    SecureUsername directly for enhanced security features.
    
    Enforces username format requirements:
    - 3-30 characters in length
    - Alphanumeric characters, underscores, hyphens only
    - Cannot start or end with underscore or hyphen
    - Case-insensitive (stored as lowercase)
    - No consecutive special characters
    
    Enhanced security features (via SecureUsername):
    - Advanced injection attack detection (SQL, LDAP, NoSQL, XSS)
    - Unicode normalization and homograph attack prevention
    - Control character filtering and sanitization
    - Reserved name and dangerous pattern blocking
    - Comprehensive security risk assessment
    - Audit logging of security violations
    """
    
    value: str
    _secure_username: SecureUsername = None
    
    # Business rule constants (maintained for compatibility)
    MIN_LENGTH: ClassVar[int] = 3
    MAX_LENGTH: ClassVar[int] = 30
    
    def __post_init__(self):
        """Validate username using enhanced security validation."""
        if not self.value:
            raise ValueError("Username cannot be empty")
        
        try:
            # Delegate to SecureUsername for comprehensive validation
            secure_username = SecureUsername(self.value)
            object.__setattr__(self, '_secure_username', secure_username)
            object.__setattr__(self, 'value', secure_username.value)
            
            logger.debug(
                "Username validation successful (via SecureUsername)",
                username=self.mask_for_logging(),
                risk_score=secure_username.get_security_metadata()['risk_score']
            )
            
        except UsernameValidationError as e:
            # Convert UsernameValidationError to ValueError for backward compatibility
            logger.warning(
                "Username validation failed with security violations",
                risk_score=e.risk_score,
                violation_count=len(e.violations),
                error_message=str(e)
            )
            raise ValueError(str(e)) from e
        except Exception as e:
            # Handle unexpected errors
            logger.error(
                "Unexpected error during username validation",
                error=str(e),
                error_type=type(e).__name__
            )
            raise ValueError("Username validation failed") from e
    
    def mask_for_logging(self) -> str:
        """Return masked username for safe logging.
        
        Returns:
            str: Masked username (first 2 chars + asterisks)
        """
        if self._secure_username:
            return self._secure_username.mask_for_logging()
        
        # Fallback for cases where SecureUsername wasn't created
        if len(self.value) <= 2:
            return "*" * len(self.value)
        return self.value[:2] + "*" * (len(self.value) - 2)
    
    def is_system_username(self) -> bool:
        """Check if this is a system/reserved username.
        
        Returns:
            bool: True if username is reserved for system use
        """
        if self._secure_username:
            return self._secure_username.is_system_username()
        
        # Fallback implementation for backward compatibility
        system_usernames = {
            'admin', 'administrator', 'root', 'system', 'user',
            'guest', 'public', 'anonymous', 'test', 'demo'
        }
        return self.value in system_usernames
    
    def get_security_metadata(self) -> dict:
        """Get comprehensive security metadata for audit purposes.
        
        Returns:
            dict: Security metadata from SecureUsername validation
        """
        if self._secure_username:
            return self._secure_username.get_security_metadata()
        
        # Fallback for cases where SecureUsername wasn't created
        return {
            'risk_score': 0,
            'violations': [],
            'blocked_patterns': [],
            'is_valid': True,
            'has_critical_violations': False,
            'has_high_violations': False
        }
    
    @classmethod
    def create_safe(cls, value: str, language: str = "en") -> 'Username':
        """Create username with comprehensive safety checks.
        
        This method delegates to SecureUsername.create_safe for enhanced
        security validation while maintaining backward compatibility.
        
        Args:
            value: Raw username string
            language: Language code for localized error messages
            
        Returns:
            Username: Validated username object
            
        Raises:
            ValueError: If username fails validation or safety checks
        """
        try:
            # Use SecureUsername for enhanced validation
            secure_username = SecureUsername.create_safe(value, language)
            
            # Create Username instance with validated value
            username = cls.__new__(cls)
            object.__setattr__(username, 'value', secure_username.value)
            object.__setattr__(username, '_secure_username', secure_username)
            
            return username
            
        except UsernameValidationError as e:
            # Convert to ValueError for backward compatibility
            raise ValueError(str(e)) from e
        except Exception as e:
            # Handle unexpected errors
            logger.error(
                "Unexpected error in Username.create_safe",
                error=str(e),
                error_type=type(e).__name__
            )
            raise ValueError("Username validation failed") from e
    
    def __str__(self) -> str:
        """String representation."""
        return self.value
    
    def __eq__(self, other) -> bool:
        """Equality comparison with enhanced security-aware normalization."""
        if self._secure_username and isinstance(other, (Username, SecureUsername)):
            if hasattr(other, '_secure_username') and other._secure_username:
                return self._secure_username == other._secure_username
            elif isinstance(other, SecureUsername):
                return self._secure_username == other
        
        # Fallback to basic comparison
        if isinstance(other, Username):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other.lower()
        return False
    
    def __hash__(self) -> int:
        """Hash for use in sets and dictionaries."""
        return hash(self.value) 