"""User logout service interface.

This module defines the user logout service interface following
Domain-Driven Design principles. This interface encapsulates the business
logic for user logout operations.

Key DDD Principles Applied:
- Single Responsibility: Handles only logout logic
- Domain Value Objects: Uses AccessToken and RefreshToken value objects
- Domain Events: Publishes UserLoggedOut event
- Ubiquitous Language: Method names reflect business concepts
"""

from abc import ABC, abstractmethod

from src.domain.entities.user import User


class IUserLogoutService(ABC):
    """Interface for user logout operations.
    
    This domain service encapsulates the logic for securely logging a user out
    of the system. This is not just about clearing client-side state; it
    involves server-side revocation of tokens and sessions to ensure that
    compromised tokens cannot be reused. It also publishes a `UserLoggedOut`
    event for auditing purposes.
    
    DDD Principles:
    - Single Responsibility: Handles only logout logic
    - Domain Value Objects: Uses AccessToken and RefreshToken value objects
    - Domain Events: Publishes UserLoggedOut event
    - Ubiquitous Language: Method names reflect business concepts
    """

    @abstractmethod
    async def logout_user(
        self,
        access_token: "AccessToken",  # Forward reference to avoid circular imports
        refresh_token: "RefreshToken",  # Forward reference to avoid circular imports
        user: User,
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> None:
        """Logs a user out by revoking their tokens and session.

        Args:
            access_token: The user's `AccessToken` to be revoked.
            refresh_token: The user's `RefreshToken` to be revoked.
            user: The `User` entity who is logging out.
            language: The language for any potential messages.
            client_ip: The client's IP address for auditing.
            user_agent: The client's user agent for auditing.
            correlation_id: A unique ID for tracing the request.
        """
        raise NotImplementedError 