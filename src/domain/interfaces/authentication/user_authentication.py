"""User authentication service interface.

This module defines the user authentication service interface following
Domain-Driven Design principles. This interface encapsulates the business
logic for user authentication operations.

Key DDD Principles Applied:
- Single Responsibility: Handles only user authentication logic
- Domain Value Objects: Uses Username and Password value objects
- Domain Events: Publishes authentication events for audit trails
- Ubiquitous Language: Method names reflect business concepts
"""

from abc import ABC, abstractmethod

from src.domain.entities.user import User
from src.domain.value_objects.password import Password
from src.domain.value_objects.username import Username


class IUserAuthenticationService(ABC):
    """Interface for user authentication operations.
    
    This domain service is responsible for the core logic of authenticating a
    user based on their credentials. It uses value objects for inputs to ensure
    that only valid data enters the domain logic. It also plays a role in
    security by publishing domain events for successful and failed login
    attempts, which can be used for auditing and monitoring.
    
    DDD Principles:
    - Single Responsibility: Handles only authentication logic
    - Domain Value Objects: Uses Username and Password value objects
    - Domain Events: Publishes authentication events for audit trails
    - Ubiquitous Language: Method names reflect business concepts
    """

    @abstractmethod
    async def authenticate_user(
        self,
        username: Username,
        password: Password,
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> User:
        """Authenticates a user with their username and password.

        This method encapsulates the process of:
        1. Finding the user by their username.
        2. Verifying their password against the stored hash.
        3. Checking if the user's account is active.
        4. Publishing relevant domain events for the authentication attempt.

        Args:
            username: The validated and normalized `Username` value object.
            password: The validated `Password` value object.
            language: The language for error messages (i18n).
            client_ip: The IP address of the client for auditing.
            user_agent: The user agent of the client for auditing.
            correlation_id: A unique ID for tracing the request.

        Returns:
            The authenticated `User` entity if successful.

        Raises:
            AuthenticationError: If the credentials are invalid, the user is
                not found, or the account is inactive.
        """
        raise NotImplementedError

    @abstractmethod
    async def verify_password(self, user: User, password: Password) -> bool:
        """Verifies a user's password against their stored hash.

        This method provides a way to check a password without performing a
        full authentication, which can be useful in scenarios like confirming
        a user's identity before a sensitive operation.

        Args:
            user: The `User` entity whose password is to be verified.
            password: The `Password` value object to check.

        Returns:
            `True` if the password is correct, `False` otherwise.
        """
        raise NotImplementedError 