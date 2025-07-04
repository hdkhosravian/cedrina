"""OAuth User Info Value Object.

This module defines the OAuthUserInfo value object that encapsulates
OAuth user information validation and business rules following Domain-Driven Design principles.

The OAuthUserInfo value object ensures:
- User info structure validation
- Required fields validation (email, user ID)
- Email format validation
- Immutability of user data
- Business rule validation
- Secure logging with data masking
"""

from typing import Any, Dict, Optional

import structlog

from src.domain.value_objects.email import Email

logger = structlog.get_logger(__name__)


class OAuthUserInfo:
    """OAuth User Info value object following DDD principles.
    
    This value object encapsulates OAuth user information validation and business rules:
    - Validates user info structure and required fields
    - Ensures email format is valid
    - Validates user ID presence
    - Ensures immutability of user data
    - Implements secure logging with data masking
    - Follows ubiquitous language from the domain
    
    Security Features:
    - User info validation prevents invalid data usage
    - Email validation ensures proper format
    - Immutable design prevents runtime modification
    - Secure logging masks sensitive user data
    """
    
    def __init__(self, user_info: Dict[str, Any]):
        """Initialize OAuth user info with validation.
        
        Args:
            user_info: OAuth user info dictionary from provider
            
        Raises:
            ValueError: If user info is invalid or missing required fields
            
        Note:
            User info must contain at least 'email' and either 'sub' or 'id' fields.
            The email field must be a valid email format.
        """
        if not user_info:
            raise ValueError("OAuth user info cannot be empty")
        
        if not isinstance(user_info, dict):
            raise ValueError("OAuth user info must be a dictionary")
        
        # Validate required fields
        if "email" not in user_info:
            raise ValueError("OAuth user info must contain 'email' field")
        
        # Check for user ID (either 'sub' for OpenID Connect or 'id' for OAuth)
        provider_user_id = user_info.get("sub") or user_info.get("id")
        if not provider_user_id:
            raise ValueError("OAuth user info must contain 'sub' or 'id' field")
        
        # Validate email using Email value object
        try:
            email = Email.create_normalized(user_info["email"])
        except ValueError as e:
            raise ValueError(f"Invalid email in OAuth user info: {e}")
        
        self._user_info = user_info.copy()  # Create a copy for immutability
        self._email = email
        self._provider_user_id = str(provider_user_id)
        self._name = user_info.get("name")
        self._given_name = user_info.get("given_name")
        self._family_name = user_info.get("family_name")
        self._picture = user_info.get("picture")
        self._locale = user_info.get("locale")
        
        logger.debug(
            "OAuth user info value object created",
            email=self._email.mask_for_logging(),
            provider_user_id=self._provider_user_id[:10] + "***",
            has_name=bool(self._name),
            has_picture=bool(self._picture),
            validation_passed=True
        )
    
    @property
    def email(self) -> Email:
        """Get the user's email.
        
        Returns:
            Email: The validated email value object
        """
        return self._email
    
    @property
    def provider_user_id(self) -> str:
        """Get the provider's user ID.
        
        Returns:
            str: The provider's unique user identifier
        """
        return self._provider_user_id
    
    @property
    def name(self) -> Optional[str]:
        """Get the user's full name.
        
        Returns:
            Optional[str]: The user's full name or None
        """
        return self._name
    
    @property
    def given_name(self) -> Optional[str]:
        """Get the user's given name (first name).
        
        Returns:
            Optional[str]: The user's given name or None
        """
        return self._given_name
    
    @property
    def family_name(self) -> Optional[str]:
        """Get the user's family name (last name).
        
        Returns:
            Optional[str]: The user's family name or None
        """
        return self._family_name
    
    @property
    def picture(self) -> Optional[str]:
        """Get the user's profile picture URL.
        
        Returns:
            Optional[str]: The user's profile picture URL or None
        """
        return self._picture
    
    @property
    def locale(self) -> Optional[str]:
        """Get the user's locale.
        
        Returns:
            Optional[str]: The user's locale or None
        """
        return self._locale
    
    def get_display_name(self) -> str:
        """Get the best available display name.
        
        Returns:
            str: The user's display name (name, given_name, or email)
        """
        if self._name:
            return self._name
        elif self._given_name:
            return self._given_name
        else:
            return str(self._email)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user info to dictionary.
        
        Returns:
            Dict[str, Any]: User info dictionary
        """
        return self._user_info.copy()
    
    def mask_for_logging(self) -> Dict[str, Any]:
        """Get a masked version of the user info for secure logging.
        
        Returns:
            Dict[str, Any]: Masked user info for logging
        """
        return {
            "email": self._email.mask_for_logging(),
            "provider_user_id": f"{self._provider_user_id[:10]}***",
            "name": self._name[:10] + "***" if self._name else None,
            "given_name": self._given_name[:10] + "***" if self._given_name else None,
            "family_name": self._family_name[:10] + "***" if self._family_name else None,
            "has_picture": bool(self._picture),
            "locale": self._locale,
        }
    
    def __str__(self) -> str:
        """String representation of the user info.
        
        Returns:
            str: User email and provider ID
        """
        return f"OAuthUserInfo(email={self._email}, provider_user_id={self._provider_user_id[:10]}***)"
    
    def __repr__(self) -> str:
        """Representation of the user info.
        
        Returns:
            str: User info representation
        """
        return f"OAuthUserInfo(email='{self._email}', provider_user_id='{self._provider_user_id[:10]}***')"
    
    def __eq__(self, other: object) -> bool:
        """Equality comparison.
        
        Args:
            other: Object to compare with
            
        Returns:
            bool: True if user info objects are equal
        """
        if not isinstance(other, OAuthUserInfo):
            return False
        return (
            self._email == other._email and
            self._provider_user_id == other._provider_user_id and
            self._name == other._name and
            self._given_name == other._given_name and
            self._family_name == other._family_name and
            self._picture == other._picture and
            self._locale == other._locale
        )
    
    def __hash__(self) -> int:
        """Hash value for the user info.
        
        Returns:
            int: Hash value
        """
        return hash((
            self._email,
            self._provider_user_id,
            self._name,
            self._given_name,
            self._family_name,
            self._picture,
            self._locale
        ))
    
    @classmethod
    def create_safe(cls, user_info: Dict[str, Any]) -> 'OAuthUserInfo':
        """Create OAuth user info with safe validation.
        
        Args:
            user_info: User info dictionary
            
        Returns:
            OAuthUserInfo: Validated user info value object
            
        Raises:
            ValueError: If user info is invalid
        """
        return cls(user_info) 