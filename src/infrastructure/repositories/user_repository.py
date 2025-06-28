"""User Repository implementation using SQLAlchemy.

This module provides a repository pattern implementation for User entity operations,
abstracting database access and providing a clean interface for domain services.
"""

from abc import ABC, abstractmethod
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog import get_logger

from src.domain.entities.user import User

logger = get_logger(__name__)


class UserRepositoryInterface(ABC):
    """Abstract interface for User repository operations.
    
    Defines the contract for user data access operations following
    the Repository pattern from Domain-Driven Design.
    """
    
    @abstractmethod
    async def get_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        pass
    
    @abstractmethod
    async def get_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        pass
    
    @abstractmethod
    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email address."""
        pass
    
    @abstractmethod
    async def get_by_password_reset_token(self, token: str) -> Optional[User]:
        """Get user by password reset token."""
        pass
    
    @abstractmethod
    async def save(self, user: User) -> User:
        """Save or update user."""
        pass
    
    @abstractmethod
    async def get_by_reset_token(self, token: str) -> Optional[User]:
        """Get user by password reset token."""
        pass
    
    @abstractmethod
    async def get_users_with_reset_tokens(self) -> list[User]:
        """Get all users with active password reset tokens."""
        pass
    
    @abstractmethod
    async def delete(self, user: User) -> None:
        """Delete user."""
        pass


class UserRepository(UserRepositoryInterface):
    """SQLAlchemy implementation of UserRepository.
    
    Provides concrete implementation of user data access operations
    using SQLAlchemy async sessions following existing patterns.
    """
    
    def __init__(self, db_session: AsyncSession):
        """Initialize repository with database session.
        
        Args:
            db_session: SQLAlchemy async session
        """
        self.db_session = db_session
        logger.debug("UserRepository initialized")
    
    async def get_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID.
        
        Args:
            user_id: User ID to search for
            
        Returns:
            User entity if found, None otherwise
        """
        try:
            statement = select(User).where(User.id == user_id)
            result = await self.db_session.execute(statement)
            user = result.scalars().first()
            
            logger.debug("User lookup by ID", user_id=user_id, found=user is not None)
            return user
            
        except Exception as e:
            logger.error("Error getting user by ID", user_id=user_id, error=str(e))
            raise
    
    async def get_by_username(self, username: str) -> Optional[User]:
        """Get user by username (case-insensitive).
        
        Args:
            username: Username to search for
            
        Returns:
            User entity if found, None otherwise
        """
        try:
            statement = select(User).where(User.username == username.lower())
            result = await self.db_session.execute(statement)
            user = result.scalars().first()
            
            logger.debug("User lookup by username", username=username, found=user is not None)
            return user
            
        except Exception as e:
            logger.error("Error getting user by username", username=username, error=str(e))
            raise
    
    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email address (case-insensitive).
        
        Args:
            email: Email address to search for
            
        Returns:
            User entity if found, None otherwise
        """
        try:
            statement = select(User).where(User.email == email.lower())
            result = await self.db_session.execute(statement)
            user = result.scalars().first()
            
            logger.debug("User lookup by email", email=email, found=user is not None)
            return user
            
        except Exception as e:
            logger.error("Error getting user by email", email=email, error=str(e))
            raise
    
    async def get_by_password_reset_token(self, token: str) -> Optional[User]:
        """Get user by password reset token.
        
        Args:
            token: Password reset token to search for
            
        Returns:
            User entity if found, None otherwise
        """
        try:
            statement = select(User).where(User.password_reset_token == token)
            result = await self.db_session.execute(statement)
            user = result.scalars().first()
            
            logger.debug(
                "User lookup by reset token", 
                token_prefix=token[:8] if token else None, 
                found=user is not None
            )
            return user
            
        except Exception as e:
            logger.error(
                "Error getting user by reset token", 
                token_prefix=token[:8] if token else None, 
                error=str(e)
            )
            raise
    
    async def save(self, user: User) -> User:
        """Save or update user.
        
        Args:
            user: User entity to save
            
        Returns:
            Saved user entity
        """
        try:
            if user.id is None:
                # New user - add to session
                self.db_session.add(user)
                logger.debug("Adding new user", username=user.username, email=user.email)
            else:
                # Existing user - merge changes
                logger.debug("Updating existing user", user_id=user.id, username=user.username)
            
            await self.db_session.commit()
            await self.db_session.refresh(user)
            
            logger.info("User saved successfully", user_id=user.id, username=user.username)
            return user
            
        except Exception as e:
            await self.db_session.rollback()
            logger.error(
                "Error saving user", 
                user_id=user.id, 
                username=user.username, 
                error=str(e)
            )
            raise
    
    async def get_by_reset_token(self, token: str) -> Optional[User]:
        """Get user by password reset token.
        
        Args:
            token: Password reset token to search for
            
        Returns:
            User entity if found, None otherwise
        """
        try:
            statement = select(User).where(User.password_reset_token == token)
            result = await self.db_session.execute(statement)
            user = result.scalars().first()
            
            logger.debug(
                "User lookup by reset token", 
                token_prefix=token[:8] if token else None, 
                found=user is not None
            )
            return user
            
        except Exception as e:
            logger.error(
                "Error getting user by reset token", 
                token_prefix=token[:8] if token else None, 
                error=str(e)
            )
            raise
    
    async def get_users_with_reset_tokens(self) -> list[User]:
        """Get all users with active password reset tokens."""
        try:
            statement = select(User).where(User.password_reset_token != None)
            result = await self.db_session.execute(statement)
            users = result.scalars().all()
            
            logger.debug("Users lookup with reset tokens", count=len(users))
            return users
            
        except Exception as e:
            logger.error("Error getting users with reset tokens", error=str(e))
            raise
    
    async def delete(self, user: User) -> None:
        """Delete user.
        
        Args:
            user: User entity to delete
        """
        try:
            await self.db_session.delete(user)
            await self.db_session.commit()
            
            logger.info("User deleted successfully", user_id=user.id, username=user.username)
            
        except Exception as e:
            await self.db_session.rollback()
            logger.error(
                "Error deleting user", 
                user_id=user.id, 
                username=user.username, 
                error=str(e)
            )
            raise 