"""Repository interfaces for domain data access.

These interfaces define contracts for data access operations,
allowing the domain layer to remain independent of infrastructure concerns.
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from pydantic import EmailStr

from src.domain.entities.user import User
from src.domain.entities.oauth_profile import OAuthProfile, Provider


class IUserRepository(ABC):
    """Interface for user repository operations.
    
    Defines the contract for user data access operations following
    the Repository pattern from Domain-Driven Design.
    """
    
    @abstractmethod
    async def get_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID.
        
        Args:
            user_id: User ID to search for
            
        Returns:
            User entity if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def get_by_username(self, username: str) -> Optional[User]:
        """Get user by username (case-insensitive).
        
        Args:
            username: Username to search for (string or Username value object)
            
        Returns:
            User entity if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email address (case-insensitive).
        
        Args:
            email: Email address to search for (string or Email value object)
            
        Returns:
            User entity if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def get_by_reset_token(self, token: str) -> Optional[User]:
        """Get user by password reset token.
        
        Args:
            token: Password reset token to search for
            
        Returns:
            User entity if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def get_users_with_reset_tokens(self) -> List[User]:
        """Get all users with active password reset tokens.
        
        Returns:
            List of users with reset tokens
        """
        pass
    
    @abstractmethod
    async def save(self, user: User) -> User:
        """Save or update user.
        
        Args:
            user: User entity to save
            
        Returns:
            Saved user entity
        """
        pass
    
    @abstractmethod
    async def delete(self, user: User) -> None:
        """Delete user.
        
        Args:
            user: User entity to delete
        """
        pass
    
    @abstractmethod
    async def check_username_availability(self, username: str) -> bool:
        """Check if username is available for registration.
        
        Args:
            username: Username to check (string or Username value object)
            
        Returns:
            True if username is available, False otherwise
        """
        pass
    
    @abstractmethod
    async def check_email_availability(self, email: str) -> bool:
        """Check if email is available for registration.
        
        Args:
            email: Email to check (string or Email value object)
            
        Returns:
            True if email is available, False otherwise
        """
        pass

class IOAuthProfileRepository(ABC):
    """Interface for OAuth profile repository following DDD principles.
    
    This repository handles OAuth profile data access operations
    using domain entities and following repository pattern.
    """
    
    @abstractmethod
    async def get_by_provider_and_user_id(
        self, 
        provider: Provider, 
        provider_user_id: str
    ) -> Optional[OAuthProfile]:
        """Get OAuth profile by provider and provider user ID.
        
        Args:
            provider: OAuth provider
            provider_user_id: Provider's user ID
            
        Returns:
            Optional[OAuthProfile]: OAuth profile if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def get_by_user_id(self, user_id: int) -> List[OAuthProfile]:
        """Get all OAuth profiles for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List[OAuthProfile]: List of OAuth profiles for the user
        """
        pass
    
    @abstractmethod
    async def create(self, oauth_profile: OAuthProfile) -> OAuthProfile:
        """Create a new OAuth profile.
        
        Args:
            oauth_profile: OAuth profile to create
            
        Returns:
            OAuthProfile: Created OAuth profile with ID
            
        Raises:
            DuplicateUserError: If OAuth profile already exists
        """
        pass
    
    @abstractmethod
    async def update(self, oauth_profile: OAuthProfile) -> OAuthProfile:
        """Update an existing OAuth profile.
        
        Args:
            oauth_profile: OAuth profile to update
            
        Returns:
            OAuthProfile: Updated OAuth profile
            
        Raises:
            UserNotFoundError: If OAuth profile not found
        """
        pass
    
    @abstractmethod
    async def delete(self, oauth_profile_id: int) -> None:
        """Delete an OAuth profile.
        
        Args:
            oauth_profile_id: OAuth profile ID to delete
            
        Raises:
            UserNotFoundError: If OAuth profile not found
        """
        pass 