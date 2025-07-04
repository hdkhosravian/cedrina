"""User registration service interface.

This module defines the user registration service interface following
Domain-Driven Design principles. This interface encapsulates the business
logic for user registration operations.

Key DDD Principles Applied:
- Single Responsibility: Handles only user registration logic
- Domain Value Objects: Uses Username, Email, and Password value objects
- Domain Events: Publishes UserRegistered event
- Ubiquitous Language: Method names reflect business concepts
"""

from abc import ABC, abstractmethod
from typing import Optional

from src.domain.entities.user import Role, User
from src.domain.value_objects.email import Email
from src.domain.value_objects.password import Password
from src.domain.value_objects.username import Username


class IUserRegistrationService(ABC):
    """Interface for user registration operations.
    
    This domain service encapsulates the business logic for creating a new user.
    It ensures that all invariants for a new user are met before persistence,
    such as checking for username and email availability. It also publishes a
    `UserRegistered` event upon successful creation.
    
    DDD Principles:
    - Single Responsibility: Handles only user registration logic
    - Domain Value Objects: Uses Username, Email, and Password value objects
    - Domain Events: Publishes UserRegistered event
    - Ubiquitous Language: Method names reflect business concepts
    """

    @abstractmethod
    async def register_user(
        self,
        username: Username,
        email: Email,
        password: Password,
        language: str = "en",
        correlation_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        role: Optional[Role] = None,
    ) -> User:
        """Creates and persists a new user.

        Args:
            username: The desired `Username` value object.
            email: The user's `Email` value object.
            password: The `Password` value object for the new account.
            language: The language for any communication (e.g., welcome email).
            correlation_id: An optional ID for tracing the request.
            user_agent: The user agent of the client for auditing.
            ip_address: The IP address of the client for auditing.
            role: The `Role` to assign to the new user. Defaults to the
                standard user role if not provided.

        Returns:
            The newly created `User` entity.

        Raises:
            DuplicateUserError: If the chosen username or email is already in use.
        """
        raise NotImplementedError

    @abstractmethod
    async def check_username_availability(self, username: str) -> bool:
        """Checks if a username is available for a new registration.

        Args:
            username: The username to check.

        Returns:
            `True` if the username is available, `False` otherwise.
        """
        raise NotImplementedError

    @abstractmethod
    async def check_email_availability(self, email: str) -> bool:
        """Checks if an email address is available for a new registration.

        Args:
            email: The email address to check.

        Returns:
            `True` if the email is available, `False` otherwise.
        """
        raise NotImplementedError 