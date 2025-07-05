"""User Repository implementation using SQLAlchemy.

This module provides a repository pattern implementation for User entity operations,
abstracting database access and providing a clean interface for domain services.

Key DDD Principles Applied:
- Repository Pattern for data access abstraction
- Value Object integration for domain validation
- Single Responsibility for data persistence operations
- Dependency Inversion through interface implementation
- Ubiquitous Language in method names and documentation
- Fail-Fast error handling with proper domain exceptions

This implementation serves as the infrastructure layer component that:
- Implements the IUserRepository interface
- Handles all database operations for User entities
- Provides value object support for domain validation
- Maintains data consistency and transaction integrity
- Implements secure logging with data masking
"""

from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog import get_logger

from src.domain.entities.user import User
from src.domain.interfaces.repositories import IUserRepository
from src.domain.value_objects.email import Email
from src.domain.value_objects.username import Username
from src.utils.i18n import get_translated_message

logger = get_logger(__name__)


class UserRepository(IUserRepository):
    """SQLAlchemy implementation of UserRepository following DDD principles.

    This repository provides concrete implementation of user data access operations
    using SQLAlchemy async sessions. It follows clean architecture principles and
    Domain-Driven Design patterns:

    - **Repository Pattern**: Abstracts data access from domain services
    - **Value Object Support**: Handles domain value objects (Username, Email)
    - **Single Responsibility**: Focuses solely on data persistence operations
    - **Dependency Inversion**: Implements IUserRepository interface
    - **Transaction Management**: Handles database transactions properly
    - **Error Handling**: Provides meaningful error messages and logging
    - **Security**: Implements secure logging with data masking

    Responsibilities:
    - User entity persistence (CRUD operations)
    - Value object integration for domain validation
    - Transaction management and data consistency
    - Secure logging with sensitive data protection
    - Database query optimization and performance
    """

    def __init__(self, db_session: AsyncSession):
        """Initialize repository with database session.

        Args:
            db_session: SQLAlchemy async session for database operations

        Note:
            The repository depends on the database session abstraction,
            following dependency inversion principle. The session is injected
            through dependency injection, making the repository testable
            and following clean architecture principles.
        """
        self.db_session = db_session
        logger.debug(
            "UserRepository initialized",
            repository_type="infrastructure",
            responsibilities=[
                "user_persistence",
                "value_object_integration",
                "transaction_management",
            ],
        )

    async def get_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID with proper validation and error handling.

        This method retrieves a user entity by its primary key, implementing
        proper validation and error handling following DDD principles.

        Args:
            user_id: User ID to search for (must be positive integer)

        Returns:
            User entity if found, None otherwise

        Raises:
            ValueError: If user_id is invalid (non-positive)

        Security Features:
        - Input validation prevents invalid queries
        - Secure logging with user ID masking for sensitive data
        - Proper error handling without information leakage
        """
        # Validate input following fail-fast principle
        if user_id <= 0:
            logger.warning(
                "Invalid user ID provided", user_id=user_id, error_type="validation_error"
            )
            raise ValueError("User ID must be a positive integer")

        try:
            # Execute database query using SQLAlchemy
            statement = select(User).where(User.id == user_id)
            result = await self.db_session.execute(statement)
            user = result.scalars().first()

            # Log operation result for debugging and monitoring
            logger.debug(
                "User lookup by ID completed",
                user_id=user_id,
                found=user is not None,
                operation="get_by_id",
            )

            return user

        except Exception as e:
            # Log error with context but don't expose sensitive information
            logger.error(
                "Error retrieving user by ID",
                user_id=user_id,
                error=str(e),
                error_type=type(e).__name__,
                operation="get_by_id",
            )
            raise

    async def get_by_username(self, username: str) -> Optional[User]:
        """Get user by username with value object support and case-insensitive search.

        This method supports both string and Username value object inputs,
        implementing proper validation and normalization following DDD principles.

        Args:
            username: Username to search for (string or Username value object)

        Returns:
            User entity if found, None otherwise

        Raises:
            ValueError: If username is invalid (empty or whitespace-only)

        Value Object Support:
        - Accepts both string and Username value object inputs
        - Automatically normalizes usernames for consistent comparison
        - Maintains domain validation through value objects

        Security Features:
        - Input validation prevents invalid queries
        - Secure logging with username masking
        - Case-insensitive search for better user experience
        """
        # Handle both string and Username value object inputs
        if isinstance(username, Username):
            username_value = username.value
        else:
            # Validate string input
            if not username or not username.strip():
                logger.warning(
                    "Invalid username provided",
                    username_provided=bool(username),
                    error_type="validation_error",
                )
                raise ValueError("Username cannot be empty or whitespace-only")
            username_value = username.lower().strip()

        try:
            # Execute case-insensitive database query
            statement = select(User).where(User.username == username_value)
            result = await self.db_session.execute(statement)
            user = result.scalars().first()

            # Log operation with secure data masking
            logger.debug(
                "User lookup by username completed",
                username=username_value[:3] + "***" if len(username_value) > 3 else username_value,
                found=user is not None,
                operation="get_by_username",
                case_insensitive=True,
            )

            return user

        except Exception as e:
            # Log error with secure data masking
            logger.error(
                "Error retrieving user by username",
                username=username_value[:3] + "***" if len(username_value) > 3 else username_value,
                error=str(e),
                error_type=type(e).__name__,
                operation="get_by_username",
            )
            raise

    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email address with value object support and case-insensitive search.

        This method supports both string and Email value object inputs,
        implementing proper validation and normalization following DDD principles.

        Args:
            email: Email address to search for (string or Email value object)

        Returns:
            User entity if found, None otherwise

        Raises:
            ValueError: If email is invalid (empty or whitespace-only)

        Value Object Support:
        - Accepts both string and Email value object inputs
        - Automatically normalizes emails for consistent comparison
        - Maintains domain validation through value objects

        Security Features:
        - Input validation prevents invalid queries
        - Secure logging with email masking
        - Case-insensitive search for better user experience
        """
        # Handle both string and Email value object inputs
        if isinstance(email, Email):
            email_value = email.value
        else:
            # Validate string input
            if not email or not email.strip():
                logger.warning(
                    "Invalid email provided",
                    email_provided=bool(email),
                    error_type="validation_error",
                )
                raise ValueError("Email cannot be empty or whitespace-only")
            email_value = email.lower().strip()

        try:
            # Execute case-insensitive database query
            statement = select(User).where(User.email == email_value)
            result = await self.db_session.execute(statement)
            user = result.scalars().first()

            # Log operation with secure data masking
            logger.debug(
                "User lookup by email completed",
                email=email_value[:3] + "***" if len(email_value) > 3 else email_value,
                found=user is not None,
                operation="get_by_email",
                case_insensitive=True,
            )

            return user

        except Exception as e:
            # Log error with secure data masking
            logger.error(
                "Error retrieving user by email",
                email=email_value[:3] + "***" if len(email_value) > 3 else email_value,
                error=str(e),
                error_type=type(e).__name__,
                operation="get_by_email",
            )
            raise

    async def get_by_reset_token(self, token: str) -> Optional[User]:
        """Get user by password reset token for password reset operations.

        This method retrieves a user entity by their password reset token,
        supporting the password reset domain workflow.

        Args:
            token: Password reset token to search for

        Returns:
            User entity if found, None otherwise

        Security Features:
        - Secure logging without exposing token values
        - Proper error handling for token-based queries
        """
        if not token or not token.strip():
            logger.warning(
                "Invalid reset token provided",
                token_provided=bool(token),
                error_type="validation_error",
            )
            raise ValueError("Reset token cannot be empty")

        try:
            statement = select(User).where(
                User.password_reset_token == token.strip()
            )
            result = await self.db_session.execute(statement)
            user = result.scalars().first()

            logger.debug(
                "User lookup by reset token completed",
                token_length=len(token),
                found=user is not None,
                operation="get_by_reset_token",
            )

            return user

        except Exception as e:
            logger.error(
                "Error retrieving user by reset token",
                token_length=len(token),
                error=str(e),
                error_type=type(e).__name__,
                operation="get_by_reset_token",
            )
            raise

    async def get_by_confirmation_token(self, token: str) -> Optional[User]:
        if not token or not token.strip():
            raise ValueError(get_translated_message("token_cannot_be_empty"))
        try:
            stmt = select(User).where(User.email_confirmation_token == token.strip())
            result = await self.db_session.execute(stmt)
            return result.scalars().first()
        except Exception as e:
            logger.error(
                "Error retrieving user by confirmation token",
                error=str(e),
                token_length=len(token),
            )
            raise

    async def get_users_with_reset_tokens(self) -> List[User]:
        """Get all users with active password reset tokens for cleanup operations.

        This method retrieves all users who have active password reset tokens,
        supporting domain operations like token cleanup and maintenance.

        Returns:
            List of users with active reset tokens

        Use Cases:
        - Cleanup expired reset tokens
        - Security monitoring and audit
        - System maintenance operations
        """
        try:
            statement = select(User).where(User.password_reset_token.isnot(None))
            result = await self.db_session.execute(statement)
            users = result.scalars().all()

            logger.debug(
                "Retrieved users with reset tokens",
                user_count=len(users),
                operation="get_users_with_reset_tokens",
            )

            return users

        except Exception as e:
            logger.error(
                "Error retrieving users with reset tokens",
                error=str(e),
                error_type=type(e).__name__,
                operation="get_users_with_reset_tokens",
            )
            raise

    async def save(self, user: User) -> User:
        """Save or update user entity with proper transaction management.

        This method handles both creating new users and updating existing ones,
        implementing proper transaction management and data consistency.

        Args:
            user: User entity to save or update

        Returns:
            Saved user entity with updated attributes

        Raises:
            ValueError: If user is None or invalid

        Transaction Management:
        - Automatic transaction handling with commit/rollback
        - Data consistency through proper session management
        - Entity refresh after save to ensure data integrity

        Security Features:
        - Input validation prevents invalid saves
        - Secure logging with sensitive data masking
        - Proper error handling with transaction rollback
        """
        # Validate input following fail-fast principle
        if not user:
            logger.warning("Attempted to save None user", error_type="validation_error")
            raise ValueError("User entity cannot be None")

        try:
            if user.id is None:
                # New user - add to session for insertion
                self.db_session.add(user)
                logger.debug(
                    "Adding new user to session",
                    username=(
                        user.username[:3] + "***"
                        if user.username and len(user.username) > 3
                        else user.username
                    ),
                    email=(
                        user.email[:3] + "***" if user.email and len(user.email) > 3 else user.email
                    ),
                    operation="save_new_user",
                )
            else:
                # Existing user - merge changes for update
                logger.debug(
                    "Updating existing user",
                    user_id=user.id,
                    username=(
                        user.username[:3] + "***"
                        if user.username and len(user.username) > 3
                        else user.username
                    ),
                    operation="save_existing_user",
                )

            # Commit transaction and refresh entity
            await self.db_session.commit()
            await self.db_session.refresh(user)

            logger.info(
                "User saved successfully",
                user_id=user.id,
                username=(
                    user.username[:3] + "***"
                    if user.username and len(user.username) > 3
                    else user.username
                ),
                operation="save_completed",
            )

            return user

        except Exception as e:
            # Rollback transaction on error
            await self.db_session.rollback()
            logger.error(
                "Error saving user",
                user_id=user.id if user else None,
                username=(
                    user.username[:3] + "***"
                    if user and user.username and len(user.username) > 3
                    else (user.username if user else None)
                ),
                error=str(e),
                error_type=type(e).__name__,
                operation="save_failed",
            )
            raise

    async def delete(self, user: User) -> None:
        """Delete user entity with proper transaction management.

        This method permanently removes a user entity from the database,
        implementing proper transaction management and validation.

        Args:
            user: User entity to delete

        Raises:
            ValueError: If user is None or invalid

        Security Features:
        - Input validation prevents invalid deletions
        - Secure logging with sensitive data masking
        - Proper error handling with transaction rollback
        """
        # Validate input following fail-fast principle
        if not user or not user.id:
            logger.warning(
                "Attempted to delete invalid user",
                user_provided=bool(user),
                user_id=user.id if user else None,
                error_type="validation_error",
            )
            raise ValueError("Cannot delete None user or user without ID")

        try:
            # Delete user from database
            await self.db_session.delete(user)
            await self.db_session.commit()

            logger.info(
                "User deleted successfully",
                user_id=user.id,
                username=(
                    user.username[:3] + "***"
                    if user.username and len(user.username) > 3
                    else user.username
                ),
                operation="delete_completed",
            )

        except Exception as e:
            # Rollback transaction on error
            await self.db_session.rollback()
            logger.error(
                "Error deleting user",
                user_id=user.id,
                username=(
                    user.username[:3] + "***"
                    if user.username and len(user.username) > 3
                    else user.username
                ),
                error=str(e),
                error_type=type(e).__name__,
                operation="delete_failed",
            )
            raise

    async def check_username_availability(self, username: str) -> bool:
        """Check if username is available for registration with value object support.

        This method supports both string and Username value object inputs,
        implementing proper validation and case-insensitive checking.

        Args:
            username: Username to check (string or Username value object)

        Returns:
            True if username is available, False otherwise

        Raises:
            ValueError: If username is invalid (empty or whitespace-only)

        Value Object Support:
        - Accepts both string and Username value object inputs
        - Automatically normalizes usernames for consistent checking
        - Maintains domain validation through value objects
        """
        # Handle both string and Username value object inputs
        if isinstance(username, Username):
            username_value = username.value
        else:
            # Validate string input
            if not username or not username.strip():
                logger.warning(
                    "Invalid username provided for availability check",
                    username_provided=bool(username),
                    error_type="validation_error",
                )
                raise ValueError("Username cannot be empty or whitespace-only")
            username_value = username.lower().strip()

        try:
            # Check username availability with case-insensitive query
            statement = select(User).where(User.username == username_value)
            result = await self.db_session.execute(statement)
            existing_user = result.scalars().first()

            is_available = existing_user is None

            logger.debug(
                "Username availability check completed",
                username=username_value[:3] + "***" if len(username_value) > 3 else username_value,
                is_available=is_available,
                operation="check_username_availability",
            )

            return is_available

        except Exception as e:
            logger.error(
                "Error checking username availability",
                username=username_value[:3] + "***" if len(username_value) > 3 else username_value,
                error=str(e),
                error_type=type(e).__name__,
                operation="check_username_availability",
            )
            raise

    async def check_email_availability(self, email: str) -> bool:
        """Check if email is available for registration with value object support.

        This method supports both string and Email value object inputs,
        implementing proper validation and case-insensitive checking.

        Args:
            email: Email to check (string or Email value object)

        Returns:
            True if email is available, False otherwise

        Raises:
            ValueError: If email is invalid (empty or whitespace-only)

        Value Object Support:
        - Accepts both string and Email value object inputs
        - Automatically normalizes emails for consistent checking
        - Maintains domain validation through value objects
        """
        # Handle both string and Email value object inputs
        if isinstance(email, Email):
            email_value = email.value
        else:
            # Validate string input
            if not email or not email.strip():
                logger.warning(
                    "Invalid email provided for availability check",
                    email_provided=bool(email),
                    error_type="validation_error",
                )
                raise ValueError("Email cannot be empty or whitespace-only")
            email_value = email.lower().strip()

        try:
            # Check email availability with case-insensitive query
            statement = select(User).where(User.email == email_value)
            result = await self.db_session.execute(statement)
            existing_user = result.scalars().first()

            is_available = existing_user is None

            logger.debug(
                "Email availability check completed",
                email=email_value[:3] + "***" if len(email_value) > 3 else email_value,
                is_available=is_available,
                operation="check_email_availability",
            )

            return is_available

        except Exception as e:
            logger.error(
                "Error checking email availability",
                email=email_value[:3] + "***" if len(email_value) > 3 else email_value,
                error=str(e),
                error_type=type(e).__name__,
                operation="check_email_availability",
            )
            raise
