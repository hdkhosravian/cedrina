"""OAuth service interface for third-party authentication integration.

This module defines the OAuth service interface following Domain-Driven Design
principles. This interface encapsulates the business logic for OAuth 2.0
authentication flows, provider integration, and user profile management.

Key DDD Principles Applied:
- Single Responsibility: Handles only OAuth authentication operations
- Domain Value Objects: Uses OAuthProvider, OAuthToken, and OAuthUserInfo value objects
- Domain Events: Publishes OAuth authentication events for audit trails
- Ubiquitous Language: Method names reflect business concepts
- Fail-Safe Security: Implements CSRF protection and secure token handling
"""

from abc import ABC, abstractmethod
from typing import Tuple

from src.domain.entities.oauth_profile import OAuthProfile
from src.domain.entities.user import User
from src.domain.value_objects.oauth_provider import OAuthProvider
from src.domain.value_objects.oauth_token import OAuthToken


class IOAuthService(ABC):
    """Interface for OAuth 2.0 authentication flow orchestration.
    
    This domain service is responsible for orchestrating the entire OAuth 2.0
    authentication process. This includes validating the state to prevent CSRF
    attacks, exchanging the authorization code for a token, fetching user
    information from the provider, and either linking the OAuth profile to an
    existing user or creating a new user.
    
    DDD Principles:
    - Single Responsibility: Handles only OAuth authentication operations
    - Domain Value Objects: Uses OAuthProvider, OAuthToken, and OAuthUserInfo value objects
    - Domain Events: Publishes OAuth authentication events for audit trails
    - Ubiquitous Language: Method names reflect business concepts
    - Fail-Safe Security: Implements CSRF protection and secure token handling
    """

    @abstractmethod
    async def authenticate_with_oauth(
        self,
        provider: OAuthProvider,
        token: OAuthToken,
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> Tuple[User, OAuthProfile]:
        """Authenticates a user via an OAuth provider.

        This method handles the core logic of creating or linking a user account
        based on the information received from an OAuth provider.

        Args:
            provider: The `OAuthProvider` value object (e.g., Google).
            token: The `OAuthToken` received from the provider.
            language: The language for error messages or communication.
            client_ip: The client's IP address for auditing.
            user_agent: The client's user agent for auditing.
            correlation_id: A unique ID for tracing the request.

        Returns:
            A tuple containing the authenticated `User` entity and their
            `OAuthProfile`.
        """
        raise NotImplementedError

    @abstractmethod
    async def validate_oauth_state(
        self, state: str, stored_state: str, language: str = "en"
    ) -> bool:
        """Validates the 'state' parameter to prevent CSRF attacks.

        Args:
            state: The state value received from the OAuth provider callback.
            stored_state: The state value that was originally generated and stored.
            language: The language for error messages.

        Returns:
            `True` if the states match, `False` otherwise.
        """
        raise NotImplementedError 