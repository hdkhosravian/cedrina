"""JWT Token value objects for domain modeling.

These value objects encapsulate JWT token business rules and validation,
providing type-safe representations of tokens in the domain.
"""

import secrets
import string
import base64
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, ClassVar
import hashlib
import uuid

from jwt import decode as jwt_decode, PyJWTError
from structlog import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class TokenId:
    """Value object for JWT token identifier (jti claim).
    
    Provides secure token ID generation and validation for JWT tokens.
    Advanced: 256 bits entropy, 43-char URL-safe base64, strict validation.
    """
    
    value: str
    
    # Token ID constants (RFC 7519, NIST, OAuth2 best practice)
    TOKEN_ID_LENGTH: ClassVar[int] = 43  # 32 bytes (256 bits) base64url = 43 chars (no padding)
    MIN_ENTROPY_BITS: ClassVar[int] = 256
    VALID_CHARS: ClassVar[str] = string.ascii_letters + string.digits + '-_'
    
    def __post_init__(self):
        """Validate token ID after initialization."""
        if not self.value:
            raise ValueError("Token ID cannot be empty")
        if len(self.value) != self.TOKEN_ID_LENGTH:
            raise ValueError(f"Token ID must be exactly {self.TOKEN_ID_LENGTH} characters (256 bits, base64url)")
        if not all(c in self.VALID_CHARS for c in self.value):
            raise ValueError("Token ID contains invalid characters")
    
    @classmethod
    def generate(cls) -> 'TokenId':
        """Generate a new cryptographically secure token ID (256 bits, 43-char base64url)."""
        # 32 bytes = 256 bits
        raw_bytes = secrets.token_bytes(32)
        token_id = base64.urlsafe_b64encode(raw_bytes).rstrip(b'=').decode('ascii')
        assert len(token_id) == cls.TOKEN_ID_LENGTH, f"Expected {cls.TOKEN_ID_LENGTH} chars, got {len(token_id)}"
        return cls(token_id)
    
    def get_entropy_bits(self) -> int:
        """Calculate the entropy in bits for this token ID."""
        # Each char encodes 6 bits (base64url)
        return len(self.value) * 6
    
    def is_cryptographically_secure(self) -> bool:
        """Check if this token ID meets cryptographic security requirements."""
        return len(self.value) == self.TOKEN_ID_LENGTH and self.get_entropy_bits() >= self.MIN_ENTROPY_BITS
    
    def mask_for_logging(self) -> str:
        """Return masked token ID for safe logging."""
        return self.value[:4] + '*' * (len(self.value) - 4)
    
    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class AccessToken:
    """Value object for JWT access token with validation and metadata.
    
    Encapsulates access token validation, claims extraction, and security checks.
    """
    
    token: str
    claims: Dict[str, Any]
    
    # Token validation constants
    ALGORITHM: ClassVar[str] = "RS256"
    TOKEN_TYPE: ClassVar[str] = "access"
    
    def __post_init__(self):
        """Validate token and extract claims."""
        if not self.token:
            raise ValueError("Access token cannot be empty")
        
        # Validate token structure (3 parts separated by dots)
        parts = self.token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT token format")
        
        # Validate claims if provided
        if self.claims:
            self._validate_claims()
    
    def _validate_claims(self) -> None:
        """Validate token claims."""
        required_claims = {'sub', 'exp', 'iat', 'jti', 'iss', 'aud'}
        missing_claims = required_claims - set(self.claims.keys())
        if missing_claims:
            raise ValueError(f"Missing required claims: {missing_claims}")
        
        # Validate expiration
        if self.is_expired():
            raise ValueError("Token is expired")
        
        # Validate subject
        if not self.claims.get('sub'):
            raise ValueError("Token subject cannot be empty")
    
    @classmethod
    def from_encoded(cls, token: str, public_key: str, issuer: str, audience: str) -> 'AccessToken':
        """Create AccessToken from encoded JWT string.
        
        Args:
            token: Encoded JWT token
            public_key: Public key for verification
            issuer: Expected issuer
            audience: Expected audience
            
        Returns:
            AccessToken: Validated token with claims
            
        Raises:
            ValueError: If token is invalid
        """
        try:
            claims = jwt_decode(
                token,
                public_key,
                algorithms=[cls.ALGORITHM],
                issuer=issuer,
                audience=audience
            )
            return cls(token=token, claims=claims)
        except PyJWTError as e:
            raise ValueError(f"Invalid access token: {str(e)}")
    
    def get_user_id(self) -> int:
        """Extract user ID from token claims.
        
        Returns:
            int: User ID from subject claim
        """
        return int(self.claims['sub'])
    
    def get_username(self) -> Optional[str]:
        """Extract username from token claims.
        
        Returns:
            Optional[str]: Username if present in claims
        """
        return self.claims.get('username')
    
    def get_role(self) -> Optional[str]:
        """Extract user role from token claims.
        
        Returns:
            Optional[str]: User role if present in claims
        """
        return self.claims.get('role')
    
    def get_token_id(self) -> TokenId:
        """Extract token ID from claims.
        
        Returns:
            TokenId: Token identifier
        """
        return TokenId(self.claims['jti'])
    
    def is_expired(self) -> bool:
        """Check if token is expired.
        
        Returns:
            bool: True if token is expired
        """
        exp = self.claims.get('exp')
        if not exp:
            return True
        
        expiry_time = datetime.fromtimestamp(exp, tz=timezone.utc)
        return datetime.now(timezone.utc) > expiry_time
    
    def time_until_expiry(self) -> Optional[timedelta]:
        """Get time until token expires.
        
        Returns:
            Optional[timedelta]: Time until expiry, None if already expired
        """
        exp = self.claims.get('exp')
        if not exp:
            return None
        
        expiry_time = datetime.fromtimestamp(exp, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        
        if now > expiry_time:
            return None
        
        return expiry_time - now
    
    def mask_for_logging(self) -> str:
        """Return masked token for safe logging.
        
        Returns:
            str: Masked token (first 10 chars + asterisks)
        """
        if len(self.token) <= 10:
            return '*' * len(self.token)
        return self.token[:10] + '*' * (len(self.token) - 10)


@dataclass(frozen=True)
class RefreshToken:
    """Value object for JWT refresh token with validation and metadata.
    
    Encapsulates refresh token validation, claims extraction, and security checks.
    """
    
    token: str
    claims: Dict[str, Any]
    
    # Token validation constants
    ALGORITHM: ClassVar[str] = "RS256"
    TOKEN_TYPE: ClassVar[str] = "refresh"
    
    def __post_init__(self):
        """Validate token and extract claims."""
        if not self.token:
            raise ValueError("Refresh token cannot be empty")
        
        # Validate token structure
        parts = self.token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT token format")
        
        # Validate claims if provided
        if self.claims:
            self._validate_claims()
    
    def _validate_claims(self) -> None:
        """Validate token claims."""
        required_claims = {'sub', 'exp', 'iat', 'jti', 'iss', 'aud'}
        missing_claims = required_claims - set(self.claims.keys())
        if missing_claims:
            raise ValueError(f"Missing required claims: {missing_claims}")
        
        # Validate expiration
        if self.is_expired():
            raise ValueError("Token is expired")
        
        # Validate subject
        if not self.claims.get('sub'):
            raise ValueError("Token subject cannot be empty")
    
    @classmethod
    def from_encoded(cls, token: str, public_key: str, issuer: str, audience: str) -> 'RefreshToken':
        """Create RefreshToken from encoded JWT string.
        
        Args:
            token: Encoded JWT token
            public_key: Public key for verification
            issuer: Expected issuer
            audience: Expected audience
            
        Returns:
            RefreshToken: Validated token with claims
            
        Raises:
            ValueError: If token is invalid
        """
        try:
            claims = jwt_decode(
                token,
                public_key,
                algorithms=[cls.ALGORITHM],
                issuer=issuer,
                audience=audience
            )
            return cls(token=token, claims=claims)
        except PyJWTError as e:
            raise ValueError(f"Invalid refresh token: {str(e)}")
    
    def get_user_id(self) -> int:
        """Extract user ID from token claims.
        
        Returns:
            int: User ID from subject claim
        """
        return int(self.claims['sub'])
    
    def get_token_id(self) -> TokenId:
        """Extract token ID from claims.
        
        Returns:
            TokenId: Token identifier
        """
        return TokenId(self.claims['jti'])
    
    def is_expired(self) -> bool:
        """Check if token is expired.
        
        Returns:
            bool: True if token is expired
        """
        exp = self.claims.get('exp')
        if not exp:
            return True
        
        expiry_time = datetime.fromtimestamp(exp, tz=timezone.utc)
        return datetime.now(timezone.utc) > expiry_time
    
    def get_hash(self) -> str:
        """Get SHA256 hash of the token for storage.
        
        Returns:
            str: Hex-encoded SHA256 hash
        """
        import hashlib
        return hashlib.sha256(self.token.encode()).hexdigest()
    
    def mask_for_logging(self) -> str:
        """Return masked token for safe logging.
        
        Returns:
            str: Masked token (first 10 chars + asterisks)
        """
        if len(self.token) <= 10:
            return '*' * len(self.token)
        return self.token[:10] + '*' * (len(self.token) - 10) 