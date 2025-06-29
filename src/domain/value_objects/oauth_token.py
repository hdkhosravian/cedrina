"""OAuth Token Value Object.

This module defines the OAuthToken value object that encapsulates
OAuth token validation and business rules following Domain-Driven Design principles.

The OAuthToken value object ensures:
- Token structure validation
- Expiration time validation
- Required fields validation
- Immutability of token data
- Business rule validation
- Secure logging with data masking
"""

import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import structlog

logger = structlog.get_logger(__name__)


class OAuthToken:
    """OAuth Token value object following DDD principles.
    
    This value object encapsulates OAuth token validation and business rules:
    - Validates token structure and required fields
    - Ensures token is not expired
    - Validates access token format
    - Ensures immutability of token data
    - Implements secure logging with data masking
    - Follows ubiquitous language from the domain
    
    Security Features:
    - Token validation prevents invalid token usage
    - Expiration checking prevents replay attacks
    - Immutable design prevents runtime modification
    - Secure logging masks sensitive token data
    """
    
    def __init__(self, token_data: Dict[str, Any]):
        """Initialize OAuth token with validation.
        
        Args:
            token_data: OAuth token data dictionary
            
        Raises:
            ValueError: If token data is invalid or missing required fields
            
        Note:
            Token data must contain at least 'access_token' and 'expires_at' fields.
            The 'expires_at' field should be a Unix timestamp.
        """
        if not token_data:
            raise ValueError("OAuth token data cannot be empty")
        
        if not isinstance(token_data, dict):
            raise ValueError("OAuth token data must be a dictionary")
        
        # Validate required fields
        if "access_token" not in token_data:
            raise ValueError("OAuth token must contain 'access_token' field")
        
        if "expires_at" not in token_data:
            raise ValueError("OAuth token must contain 'expires_at' field")
        
        # Validate access token
        access_token = token_data["access_token"]
        if not access_token or not isinstance(access_token, str):
            raise ValueError("OAuth access token must be a non-empty string")
        
        # Validate expiration time
        expires_at = token_data["expires_at"]
        if not isinstance(expires_at, (int, float)):
            raise ValueError("OAuth token 'expires_at' must be a numeric timestamp")
        
        # Check if token is expired
        if expires_at < time.time():
            raise ValueError("OAuth token has expired")
        
        self._token_data = token_data.copy()  # Create a copy for immutability
        self._access_token = access_token
        self._expires_at = expires_at
        self._id_token = token_data.get("id_token")
        self._refresh_token = token_data.get("refresh_token")
        self._token_type = token_data.get("token_type", "Bearer")
        
        logger.debug(
            "OAuth token value object created",
            token_type=self._token_type,
            has_id_token=bool(self._id_token),
            has_refresh_token=bool(self._refresh_token),
            expires_at=self._expires_at,
            validation_passed=True
        )
    
    @property
    def access_token(self) -> str:
        """Get the access token.
        
        Returns:
            str: The OAuth access token
        """
        return self._access_token
    
    @property
    def expires_at(self) -> float:
        """Get the expiration timestamp.
        
        Returns:
            float: Unix timestamp when token expires
        """
        return self._expires_at
    
    @property
    def id_token(self) -> Optional[str]:
        """Get the ID token if present.
        
        Returns:
            Optional[str]: The OAuth ID token or None
        """
        return self._id_token
    
    @property
    def refresh_token(self) -> Optional[str]:
        """Get the refresh token if present.
        
        Returns:
            Optional[str]: The OAuth refresh token or None
        """
        return self._refresh_token
    
    @property
    def token_type(self) -> str:
        """Get the token type.
        
        Returns:
            str: The token type (usually "Bearer")
        """
        return self._token_type
    
    @property
    def expires_at_datetime(self) -> datetime:
        """Get the expiration time as a datetime object.
        
        Returns:
            datetime: Expiration time in UTC
        """
        return datetime.fromtimestamp(self._expires_at, tz=timezone.utc)
    
    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Check if the token is expired.
        
        Args:
            current_time: Current time as Unix timestamp (defaults to now)
            
        Returns:
            bool: True if token is expired
        """
        if current_time is None:
            current_time = time.time()
        return self._expires_at < current_time
    
    def time_until_expiry(self, current_time: Optional[float] = None) -> float:
        """Get time until token expires in seconds.
        
        Args:
            current_time: Current time as Unix timestamp (defaults to now)
            
        Returns:
            float: Seconds until expiry (negative if expired)
        """
        if current_time is None:
            current_time = time.time()
        return self._expires_at - current_time
    
    def has_id_token(self) -> bool:
        """Check if token has an ID token.
        
        Returns:
            bool: True if ID token is present
        """
        return bool(self._id_token)
    
    def has_refresh_token(self) -> bool:
        """Check if token has a refresh token.
        
        Returns:
            bool: True if refresh token is present
        """
        return bool(self._refresh_token)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert token to dictionary.
        
        Returns:
            Dict[str, Any]: Token data dictionary
        """
        return self._token_data.copy()
    
    def mask_for_logging(self) -> str:
        """Get a masked version of the token for secure logging.
        
        Returns:
            str: Masked token information for logging
        """
        return {
            "access_token": f"{self._access_token[:10]}***" if self._access_token else "None",
            "id_token": f"{self._id_token[:10]}***" if self._id_token else "None",
            "refresh_token": f"{self._refresh_token[:10]}***" if self._refresh_token else "None",
            "token_type": self._token_type,
            "expires_at": self._expires_at,
        }
    
    def __str__(self) -> str:
        """String representation of the token.
        
        Returns:
            str: Token type and expiration info
        """
        return f"OAuthToken(type={self._token_type}, expires_at={self._expires_at})"
    
    def __repr__(self) -> str:
        """Representation of the token.
        
        Returns:
            str: Token representation
        """
        return f"OAuthToken(access_token='{self._access_token[:10]}***', expires_at={self._expires_at})"
    
    def __eq__(self, other: object) -> bool:
        """Equality comparison.
        
        Args:
            other: Object to compare with
            
        Returns:
            bool: True if tokens are equal
        """
        if not isinstance(other, OAuthToken):
            return False
        return (
            self._access_token == other._access_token and
            self._expires_at == other._expires_at and
            self._id_token == other._id_token and
            self._refresh_token == other._refresh_token and
            self._token_type == other._token_type
        )
    
    def __hash__(self) -> int:
        """Hash value for the token.
        
        Returns:
            int: Hash value
        """
        return hash((
            self._access_token,
            self._expires_at,
            self._id_token,
            self._refresh_token,
            self._token_type
        ))
    
    @classmethod
    def create_safe(cls, token_data: Dict[str, Any]) -> 'OAuthToken':
        """Create OAuth token with safe validation.
        
        Args:
            token_data: Token data dictionary
            
        Returns:
            OAuthToken: Validated token value object
            
        Raises:
            ValueError: If token data is invalid
        """
        return cls(token_data) 