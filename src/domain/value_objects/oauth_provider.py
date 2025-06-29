"""OAuth Provider Value Object.

This module defines the OAuthProvider value object that encapsulates
OAuth provider validation and business rules following Domain-Driven Design principles.

The OAuthProvider value object ensures:
- Valid provider names are enforced
- Provider-specific configurations are encapsulated
- Immutability of provider data
- Business rule validation
- Secure logging with data masking
"""

from enum import Enum
from typing import Literal

import structlog

logger = structlog.get_logger(__name__)


class OAuthProviderType(str, Enum):
    """Supported OAuth provider types."""
    
    GOOGLE = "google"
    MICROSOFT = "microsoft"
    FACEBOOK = "facebook"
    
    @classmethod
    def values(cls) -> list[str]:
        """Get all valid provider values."""
        return [provider.value for provider in cls]


class OAuthProvider:
    """OAuth Provider value object following DDD principles.
    
    This value object encapsulates OAuth provider validation and business rules:
    - Validates provider names against supported providers
    - Ensures immutability of provider data
    - Provides provider-specific configurations
    - Implements secure logging with data masking
    - Follows ubiquitous language from the domain
    
    Security Features:
    - Provider validation prevents injection attacks
    - Immutable design prevents runtime modification
    - Secure logging masks sensitive provider data
    """
    
    def __init__(self, provider: str):
        """Initialize OAuth provider with validation.
        
        Args:
            provider: OAuth provider name (google, microsoft, facebook)
            
        Raises:
            ValueError: If provider is not supported or invalid
            
        Note:
            Provider names are case-sensitive and must match exactly
            the supported provider types defined in OAuthProviderType.
        """
        if not provider:
            raise ValueError("OAuth provider cannot be empty")
        
        if provider not in OAuthProviderType.values():
            raise ValueError(
                f"Unsupported OAuth provider: {provider}. "
                f"Supported providers: {', '.join(OAuthProviderType.values())}"
            )
        
        self._provider = OAuthProviderType(provider)
        
        logger.debug(
            "OAuth provider value object created",
            provider=self.mask_for_logging(),
            validation_passed=True
        )
    
    @property
    def value(self) -> str:
        """Get the provider value.
        
        Returns:
            str: The validated provider name
        """
        return self._provider.value
    
    @property
    def provider_type(self) -> OAuthProviderType:
        """Get the provider type enum.
        
        Returns:
            OAuthProviderType: The provider type enum
        """
        return self._provider
    
    def is_google(self) -> bool:
        """Check if provider is Google.
        
        Returns:
            bool: True if provider is Google
        """
        return self._provider == OAuthProviderType.GOOGLE
    
    def is_microsoft(self) -> bool:
        """Check if provider is Microsoft.
        
        Returns:
            bool: True if provider is Microsoft
        """
        return self._provider == OAuthProviderType.MICROSOFT
    
    def is_facebook(self) -> bool:
        """Check if provider is Facebook.
        
        Returns:
            bool: True if provider is Facebook
        """
        return self._provider == OAuthProviderType.FACEBOOK
    
    def get_scope(self) -> str:
        """Get the OAuth scope for this provider.
        
        Returns:
            str: The OAuth scope string
        """
        scopes = {
            OAuthProviderType.GOOGLE: "openid email profile",
            OAuthProviderType.MICROSOFT: "openid email profile",
            OAuthProviderType.FACEBOOK: "email public_profile",
        }
        return scopes[self._provider]
    
    def get_issuer(self) -> str:
        """Get the expected issuer for this provider.
        
        Returns:
            str: The expected issuer URL
        """
        issuers = {
            OAuthProviderType.GOOGLE: "https://accounts.google.com",
            OAuthProviderType.MICROSOFT: "https://login.microsoftonline.com",
            OAuthProviderType.FACEBOOK: "https://www.facebook.com",
        }
        return issuers[self._provider]
    
    def mask_for_logging(self) -> str:
        """Get a masked version of the provider for secure logging.
        
        Returns:
            str: Masked provider name for logging
        """
        return f"{self._provider.value[:3]}***"
    
    def __str__(self) -> str:
        """String representation of the provider.
        
        Returns:
            str: Provider name
        """
        return self._provider.value
    
    def __repr__(self) -> str:
        """Representation of the provider.
        
        Returns:
            str: Provider representation
        """
        return f"OAuthProvider('{self._provider.value}')"
    
    def __eq__(self, other: object) -> bool:
        """Equality comparison.
        
        Args:
            other: Object to compare with
            
        Returns:
            bool: True if providers are equal
        """
        if not isinstance(other, OAuthProvider):
            return False
        return self._provider == other._provider
    
    def __hash__(self) -> int:
        """Hash value for the provider.
        
        Returns:
            int: Hash value
        """
        return hash(self._provider)
    
    @classmethod
    def create_safe(cls, provider: str) -> 'OAuthProvider':
        """Create OAuth provider with safe validation.
        
        Args:
            provider: Provider name to validate
            
        Returns:
            OAuthProvider: Validated provider value object
            
        Raises:
            ValueError: If provider is invalid
        """
        return cls(provider)
    
    @classmethod
    def google(cls) -> 'OAuthProvider':
        """Create Google OAuth provider.
        
        Returns:
            OAuthProvider: Google provider value object
        """
        return cls(OAuthProviderType.GOOGLE.value)
    
    @classmethod
    def microsoft(cls) -> 'OAuthProvider':
        """Create Microsoft OAuth provider.
        
        Returns:
            OAuthProvider: Microsoft provider value object
        """
        return cls(OAuthProviderType.MICROSOFT.value)
    
    @classmethod
    def facebook(cls) -> 'OAuthProvider':
        """Create Facebook OAuth provider.
        
        Returns:
            OAuthProvider: Facebook provider value object
        """
        return cls(OAuthProviderType.FACEBOOK.value) 