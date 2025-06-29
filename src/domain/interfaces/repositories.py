"""Repository interfaces for domain data access.

These interfaces define contracts for data access operations,
allowing the domain layer to remain independent of infrastructure concerns.
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from pydantic import EmailStr

from src.domain.entities.user import User


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
            username: Username to search for
            
        Returns:
            User entity if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def get_by_email(self, email: EmailStr) -> Optional[User]:
        """Get user by email address (case-insensitive).
        
        Args:
            email: Email address to search for
            
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