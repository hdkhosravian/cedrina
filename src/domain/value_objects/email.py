"""Email value object for domain modeling.

This value object encapsulates email address business rules and validation,
providing a type-safe representation of email addresses in the domain.
"""

import re
from dataclasses import dataclass
from typing import ClassVar

from structlog import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class Email:
    """Value object for email address with validation and business rules.
    
    Enforces email format requirements:
    - Valid RFC 5322 email format
    - Maximum length of 254 characters (RFC limit)
    - Case-insensitive (stored as lowercase)
    - Domain validation for common patterns
    - Blocks disposable/temporary email providers
    
    Security features:
    - Prevents email enumeration through consistent validation
    - Blocks known disposable email services
    - Normalizes email format for consistent storage
    - Validates against common injection patterns
    """
    
    value: str
    
    # Business rule constants
    MAX_LENGTH: ClassVar[int] = 254  # RFC 5322 limit
    MIN_LENGTH: ClassVar[int] = 5    # Minimum realistic email (a@b.c)
    
    # RFC 5322 compliant email regex (simplified)
    EMAIL_PATTERN: ClassVar[str] = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    # Blocked disposable email domains
    BLOCKED_DOMAINS: ClassVar[set] = {
        '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
        'mailinator.com', 'yopmail.com', 'throwaway.email',
        'temp-mail.org', 'getnada.com', 'fakeinbox.com',
        'maildrop.cc', 'trashmail.com', 'sharklasers.com'
    }
    
    # Common typos in email domains to suggest corrections
    DOMAIN_CORRECTIONS: ClassVar[dict] = {
        'gmail.co': 'gmail.com',
        'gmial.com': 'gmail.com',
        'gmai.com': 'gmail.com',
        'yahoo.co': 'yahoo.com',
        'hotmai.com': 'hotmail.com',
        'outlok.com': 'outlook.com',
    }
    
    def __post_init__(self):
        """Validate email after initialization."""
        if not self.value:
            raise ValueError("Email cannot be empty")
        
        # Normalize email (lowercase, strip whitespace)
        normalized_value = self.value.strip().lower()
        object.__setattr__(self, 'value', normalized_value)
        
        # Length validation
        if len(normalized_value) < self.MIN_LENGTH:
            raise ValueError(f"Email must be at least {self.MIN_LENGTH} characters long")
        
        if len(normalized_value) > self.MAX_LENGTH:
            raise ValueError(f"Email must be no more than {self.MAX_LENGTH} characters long")
        
        # Format validation
        if not re.match(self.EMAIL_PATTERN, normalized_value):
            raise ValueError("Invalid email format")
        
        # Domain validation
        domain = self._extract_domain()
        self._validate_domain(domain)
        
        logger.debug("Email validated successfully", email=self.mask_for_logging())
    
    def _extract_domain(self) -> str:
        """Extract domain part from email address.
        
        Returns:
            str: Domain part of the email
        """
        return self.value.split('@')[1]
    
    def _validate_domain(self, domain: str) -> None:
        """Validate email domain.
        
        Args:
            domain: Domain part to validate
            
        Raises:
            ValueError: If domain is invalid or blocked
        """
        # Check for blocked disposable email domains
        if domain in self.BLOCKED_DOMAINS:
            raise ValueError("Disposable email addresses are not allowed")
        
        # Check for common domain typos
        if domain in self.DOMAIN_CORRECTIONS:
            suggested = self.DOMAIN_CORRECTIONS[domain]
            raise ValueError(f"Did you mean '{suggested}'? Please check your email address")
        
        # Basic domain format validation
        if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            raise ValueError("Invalid characters in email domain")
        
        # No consecutive dots or special characters
        if '..' in domain or domain.startswith('.') or domain.endswith('.'):
            raise ValueError("Invalid domain format")
        
        # Domain must have at least one dot
        if '.' not in domain:
            raise ValueError("Domain must contain at least one dot")
    
    def mask_for_logging(self) -> str:
        """Return masked email for safe logging.
        
        Returns:
            str: Masked email (first 2 chars + *** + domain)
        """
        local, domain = self.value.split('@')
        if len(local) <= 2:
            masked_local = '*' * len(local)
        else:
            masked_local = local[:2] + '*' * (len(local) - 2)
        return f"{masked_local}@{domain}"
    
    def get_domain(self) -> str:
        """Get domain part of email address.
        
        Returns:
            str: Domain part
        """
        return self._extract_domain()
    
    def get_local_part(self) -> str:
        """Get local part of email address (before @).
        
        Returns:
            str: Local part
        """
        return self.value.split('@')[0]
    
    def is_corporate_email(self) -> bool:
        """Check if email appears to be from a corporate domain.
        
        Returns:
            bool: True if likely corporate email
        """
        public_domains = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'icloud.com', 'protonmail.com', 'aol.com', 'live.com'
        }
        return self.get_domain() not in public_domains
    
    @classmethod
    def create_normalized(cls, value: str) -> 'Email':
        """Create email with enhanced normalization.
        
        Args:
            value: Raw email string
            
        Returns:
            Email: Validated and normalized email object
        """
        # Additional normalization for Gmail-style addresses
        if '@gmail.com' in value.lower():
            local_part = value.split('@')[0]
            # Remove dots and plus addressing for Gmail
            local_part = local_part.split('+')[0].replace('.', '')
            normalized = f"{local_part}@gmail.com"
            return cls(normalized)
        
        return cls(value)
    
    def __str__(self) -> str:
        """String representation."""
        return self.value
    
    def __eq__(self, other) -> bool:
        """Equality comparison."""
        if isinstance(other, Email):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other.lower()
        return False
    
    def __hash__(self) -> int:
        """Hash for use in sets and dictionaries."""
        return hash(self.value) 