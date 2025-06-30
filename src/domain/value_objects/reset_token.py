"""Reset Token Value Object for secure token management.

This value object encapsulates password reset token business rules,
ensuring tokens are always valid and properly formatted with enhanced security.
"""

import secrets
import string
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import ClassVar

from src.utils.i18n import get_translated_message


@dataclass(frozen=True)
class ResetToken:
    """Password reset token value object with enhanced security.
    
    This value object ensures that reset tokens are always properly
    formatted and contain sufficient entropy for security.
    
    Enhanced Security Features:
        - Variable length tokens (48-64 characters)
        - Mixed character sets (alphanumeric + special characters)
        - Cryptographically secure generation using SystemRandom
        - Format validation on construction
        - Immutable once created
        - Unpredictable token format to prevent enumeration
        - High entropy generation (>128 bits)
        - Character position randomization
        - Multiple special character sets
        
    Attributes:
        value: The token string (48-64 mixed characters)
        expires_at: Token expiration timestamp
    """
    
    value: str
    expires_at: datetime
    
    # Enhanced security constants
    MIN_TOKEN_LENGTH: ClassVar[int] = 48
    MAX_TOKEN_LENGTH: ClassVar[int] = 64
    DEFAULT_EXPIRY_MINUTES: ClassVar[int] = 5
    
    # Advanced character sets for maximum unpredictability
    UPPERCASE_CHARS: ClassVar[str] = string.ascii_uppercase
    LOWERCASE_CHARS: ClassVar[str] = string.ascii_lowercase
    DIGIT_CHARS: ClassVar[str] = string.digits
    SPECIAL_CHARS: ClassVar[str] = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    EXTENDED_SPECIAL_CHARS: ClassVar[str] = "~`!@#$%^&*()_+-=[]{}|\\;:'\",./<>?"
    
    def __post_init__(self) -> None:
        """Validate token format on construction."""
        self._validate_format()
        self._validate_expiry()
    
    def _validate_format(self) -> None:
        """Validate enhanced token format requirements.
        
        Raises:
            ValueError: If token format is invalid
        """
        if not self.value:
            raise ValueError(get_translated_message("token_cannot_be_empty"))
        
        # Validate character diversity for security first (more specific error)
        has_uppercase = any(c in self.UPPERCASE_CHARS for c in self.value)
        has_lowercase = any(c in self.LOWERCASE_CHARS for c in self.value)
        has_digit = any(c in self.DIGIT_CHARS for c in self.value)
        has_special = any(c in self.SPECIAL_CHARS for c in self.value)
        
        if not has_uppercase:
            raise ValueError(get_translated_message("token_must_contain_uppercase"))
        if not has_lowercase:
            raise ValueError(get_translated_message("token_must_contain_lowercase"))
        if not has_digit:
            raise ValueError(get_translated_message("token_must_contain_digits"))
        if not has_special:
            raise ValueError(get_translated_message("token_must_contain_special_chars"))
        
        # Validate length after character diversity
        if len(self.value) < self.MIN_TOKEN_LENGTH or len(self.value) > self.MAX_TOKEN_LENGTH:
            raise ValueError(get_translated_message("token_length_invalid").format(
                min_length=self.MIN_TOKEN_LENGTH,
                max_length=self.MAX_TOKEN_LENGTH
            ))
    
    def _validate_expiry(self) -> None:
        """Validate expiry timestamp.
        
        Raises:
            ValueError: If expiry is invalid
        """
        if not self.expires_at:
            raise ValueError(get_translated_message("token_expiry_cannot_be_empty"))
        
        if not self.expires_at.tzinfo:
            raise ValueError(get_translated_message("token_expiry_must_be_timezone_aware"))
    
    @classmethod
    def generate(cls, expiry_minutes: int = None) -> 'ResetToken':
        """Generate a new cryptographically secure reset token with advanced unpredictability.
        
        This method creates tokens with maximum security by:
        - Using SystemRandom for cryptographically secure generation
        - Variable length for unpredictability (48-64 characters)
        - Mixed character sets with extended special characters
        - Character position randomization
        - High entropy generation (>128 bits)
        - Multiple rounds of shuffling
        
        Args:
            expiry_minutes: Token expiry time in minutes (default: 5)
            
        Returns:
            ResetToken: New secure token with expiration
        """
        # Use SystemRandom for maximum security
        secure_random = secrets.SystemRandom()
        
        # Generate variable length for unpredictability
        token_length = secure_random.randint(cls.MIN_TOKEN_LENGTH, cls.MAX_TOKEN_LENGTH)
        
        # Create comprehensive character set for maximum unpredictability
        all_chars = (
            cls.UPPERCASE_CHARS + 
            cls.LOWERCASE_CHARS + 
            cls.DIGIT_CHARS + 
            cls.SPECIAL_CHARS + 
            cls.EXTENDED_SPECIAL_CHARS
        )
        
        # Ensure at least one character from each required set
        token_parts = [
            secure_random.choice(cls.UPPERCASE_CHARS),
            secure_random.choice(cls.LOWERCASE_CHARS),
            secure_random.choice(cls.DIGIT_CHARS),
            secure_random.choice(cls.SPECIAL_CHARS)
        ]
        
        # Fill remaining length with random characters from all sets
        remaining_length = token_length - len(token_parts)
        token_parts.extend(secure_random.choice(all_chars) for _ in range(remaining_length))
        
        # Multiple rounds of shuffling for maximum unpredictability
        for _ in range(3):  # Triple shuffle for enhanced security
            secure_random.shuffle(token_parts)
        
        # Final token assembly
        token_value = ''.join(token_parts)
        
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
    
    def get_security_metrics(self) -> dict:
        """Get comprehensive security metrics for the token (for monitoring).
        
        Returns:
            dict: Security metrics including entropy, complexity, and security analysis
        """
        import math
        
        # Calculate character diversity
        char_sets = {
            'uppercase': sum(1 for c in self.value if c in self.UPPERCASE_CHARS),
            'lowercase': sum(1 for c in self.value if c in self.LOWERCASE_CHARS),
            'digits': sum(1 for c in self.value if c in self.DIGIT_CHARS),
            'special': sum(1 for c in self.value if c in self.SPECIAL_CHARS),
            'extended_special': sum(1 for c in self.value if c in self.EXTENDED_SPECIAL_CHARS)
        }
        
        # Calculate entropy (approximate)
        unique_chars = len(set(self.value))
        entropy_bits = math.log2(unique_chars ** len(self.value))
        
        # Security analysis
        security_score = min(100, int(entropy_bits / 2))  # Normalize to 0-100
        
        return {
            'length': len(self.value),
            'character_diversity': char_sets,
            'unique_characters': unique_chars,
            'entropy_bits': round(entropy_bits, 2),
            'security_score': security_score,
            'format_unpredictable': True,
            'cryptographically_secure': True,
            'character_set_complexity': len(set(self.value)) / len(self.value)
        } 