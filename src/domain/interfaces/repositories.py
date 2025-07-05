"""Repository interfaces for abstracting data persistence in the domain layer.

This module defines the abstract base classes (interfaces) for repositories,
which act as a "port" in the context of Hexagonal Architecture. The domain layer
uses these interfaces to interact with persistence mechanisms without being
coupled to any specific technology (e.g., a SQL database or a NoSQL store).

The concrete implementations of these interfaces reside in the `infrastructure`
layer, acting as "adapters" that translate the domain's requests into specific
database queries.
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from pydantic import EmailStr

from src.domain.entities.user import User
from src.domain.entities.oauth_profile import OAuthProfile, Provider


class IUserRepository(ABC):
    """An interface defining the contract for user persistence operations.

    This repository is responsible for managing the lifecycle of the `User`
    aggregate root. It provides a collection-like interface for accessing and
    storing `User` entities, abstracting the underlying data store.
    """

    @abstractmethod
    async def get_by_id(self, user_id: int) -> Optional[User]:
        """Retrieves a user by their unique identifier.

        Args:
            user_id: The unique integer ID of the user.

        Returns:
            An optional `User` entity. Returns `None` if no user is found.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_by_username(self, username: str) -> Optional[User]:
        """Retrieves a user by their username (case-insensitively).

        Args:
            username: The username to search for.

        Returns:
            An optional `User` entity. Returns `None` if no user is found.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_by_email(self, email: str) -> Optional[User]:
        """Retrieves a user by their email address (case-insensitively).

        Args:
            email: The email address to search for.

        Returns:
            An optional `User` entity. Returns `None` if no user is found.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_by_reset_token(self, token: str) -> Optional[User]:
        """Retrieves a user by a valid password reset token.

        Args:
            token: The password reset token to search for.

        Returns:
            An optional `User` entity. Returns `None` if the token is invalid
            or does not correspond to any user.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_by_confirmation_token(self, token: str) -> Optional[User]:
        """Retrieve a user by email confirmation token."""
        raise NotImplementedError
    
    @abstractmethod
    async def get_users_with_reset_tokens(self) -> List[User]:
        """Retrieves all users who have an active password reset token.

        Returns:
            A list of `User` entities that have a non-expired reset token.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def save(self, user: User) -> User:
        """Persists a new user or updates an existing one.

        This method handles both creation and updates. If the `User` entity has
        an ID, it's an update; otherwise, it's a new creation.

        Args:
            user: The `User` entity to persist.

        Returns:
            The persisted `User` entity, potentially with updated state
            (e.g., a new ID or updated timestamps).
        """
        raise NotImplementedError
    
    @abstractmethod
    async def delete(self, user: User) -> None:
        """Deletes a user from the repository.

        Args:
            user: The `User` entity to delete.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def check_username_availability(self, username: str) -> bool:
        """Checks if a username is already in use.

        Args:
            username: The username to check.

        Returns:
            `True` if the username is available, `False` otherwise.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def check_email_availability(self, email: str) -> bool:
        """Checks if an email address is already in use.

        Args:
            email: The email address to check.

        Returns:
            `True` if the email is available, `False` otherwise.
        """
        raise NotImplementedError

class IOAuthProfileRepository(ABC):
    """An interface defining the contract for OAuth profile persistence.

    This repository manages the lifecycle of `OAuthProfile` entities, which link
    a `User` to an external authentication provider.
    """
    
    @abstractmethod
    async def get_by_provider_and_user_id(
        self, 
        provider: Provider, 
        provider_user_id: str
    ) -> Optional[OAuthProfile]:
        """Retrieves an OAuth profile by provider and the provider-specific user ID.
        
        Args:
            provider: The OAuth provider (e.g., Google, Microsoft).
            provider_user_id: The user's unique identifier from that provider.
            
        Returns:
            An optional `OAuthProfile` entity. Returns `None` if no matching
            profile is found.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_by_user_id(self, user_id: int) -> List[OAuthProfile]:
        """Retrieves all OAuth profiles associated with a user.
        
        Args:
            user_id: The unique ID of the user.
            
        Returns:
            A list of `OAuthProfile` entities linked to the user.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def create(self, oauth_profile: OAuthProfile) -> OAuthProfile:
        """Creates and persists a new OAuth profile.
        
        Args:
            oauth_profile: The `OAuthProfile` entity to create.
            
        Returns:
            The created `OAuthProfile` with its new ID.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def update(self, oauth_profile: OAuthProfile) -> OAuthProfile:
        """Updates an existing OAuth profile.
        
        Args:
            oauth_profile: The `OAuthProfile` entity with updated information.
            
        Returns:
            The updated `OAuthProfile` entity.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def delete(self, oauth_profile_id: int) -> None:
        """Deletes an OAuth profile by its unique identifier.
        
        Args:
            oauth_profile_id: The ID of the `OAuthProfile` to delete.
        """
        raise NotImplementedError 