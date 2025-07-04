"""Token management service interfaces for JWT and session management.

This module defines the token management service interfaces following
Domain-Driven Design principles. These interfaces encapsulate the business
logic for JWT token lifecycle, session management, and token validation.

Key DDD Principles Applied:
- Single Responsibility: Each interface has one clear purpose
- Ubiquitous Language: Interface names reflect business domain concepts
- Dependency Inversion: Domain depends on abstractions, not concretions
- Bounded Context: All interfaces belong to the token management domain
- Interface Segregation: Clients depend only on interfaces they use

Token Management Domain Services:
- Token Service: JWT access and refresh token lifecycle management
- Session Service: User session state management and validation
"""

from abc import ABC, abstractmethod
from typing import Optional, Tuple

from src.domain.entities.user import User
from src.domain.value_objects.jwt_token import AccessToken, RefreshToken


class ITokenService(ABC):
    """Interface for JWT token lifecycle management.
    
    This service is responsible for the entire lifecycle of JSON Web Tokens (JWTs),
    including creating new tokens, validating existing ones, and handling token
    refreshing and revocation. It acts as the primary authority for stateless
    authentication tokens.
    
    DDD Principles:
    - Single Responsibility: Handles only JWT token operations
    - Domain Value Objects: Uses AccessToken and RefreshToken value objects
    - Ubiquitous Language: Method names reflect business concepts
    - Fail-Safe Security: Implements secure token validation and revocation
    """

    @abstractmethod
    async def create_access_token(self, user: User) -> AccessToken:
        """Creates a new JWT access token for a user.

        Args:
            user: The `User` entity for whom the token is being created.

        Returns:
            An `AccessToken` value object containing the token string and its metadata.
        """
        raise NotImplementedError

    @abstractmethod
    async def create_refresh_token(self, user: User, jti: Optional[str] = None) -> RefreshToken:
        """Creates a new JWT refresh token.

        This token has a longer lifespan than an access token and is used to
        obtain new access tokens without requiring the user to re-authenticate.

        Args:
            user: The `User` entity for whom the token is being created.
            jti: The unique identifier of the access token, to link them.

        Returns:
            A `RefreshToken` value object containing the token string and metadata.
        """
        raise NotImplementedError

    @abstractmethod
    async def refresh_tokens(
        self, refresh_token: RefreshToken
    ) -> Tuple[AccessToken, RefreshToken]:
        """Refreshes an access token using a valid refresh token.

        Args:
            refresh_token: The `RefreshToken` provided by the client.

        Returns:
            A tuple containing a new `AccessToken` and a new `RefreshToken`.

        Raises:
            AuthenticationError: If the refresh token is invalid, expired, or revoked.
        """
        raise NotImplementedError

    @abstractmethod
    async def validate_access_token(self, token: str) -> dict:
        """Validates a JWT access token and returns its payload.

        Args:
            token: The JWT access token string to validate.

        Returns:
            A dictionary containing the token's payload if valid.

        Raises:
            AuthenticationError: If the token is invalid, expired, or has a
                bad signature.
        """
        raise NotImplementedError

    @abstractmethod
    async def revoke_refresh_token(self, token: RefreshToken, language: str = "en") -> None:
        """Revokes a refresh token.

        This action effectively ends the user's session associated with this token.

        Args:
            token: The `RefreshToken` to be revoked.
            language: The language for any potential error messages.
        """
        raise NotImplementedError

    @abstractmethod
    async def revoke_access_token(
        self, jti: str, expires_in: Optional[int] = None
    ) -> None:
        """Revokes an access token by its unique identifier (jti).

        This adds the JTI to a denylist, preventing the token from being used
        even if it has not expired.

        Args:
            jti: The unique identifier (jti claim) of the token to revoke.
            expires_in: The remaining time until the token expires, used to
                set an appropriate TTL on the denylist entry.
        """
        raise NotImplementedError

    @abstractmethod
    async def validate_token(self, token: str, language: str = "en") -> dict:
        """A generic method to validate any JWT and return its payload.

        Args:
            token: The JWT string to validate.
            language: The language for error messages.

        Returns:
            A dictionary containing the token's payload if valid.

        Raises:
            AuthenticationError: If the token is invalid in any way.
        """
        raise NotImplementedError


class ISessionService(ABC):
    """Interface for user session state management.
    
    This service is responsible for handling the lifecycle of stateful user
    sessions, which are persisted in the database. It works in concert with
    the `ITokenService` to link stateless JWTs to stateful session records,
    enabling features like session revocation and tracking active sessions.
    
    DDD Principles:
    - Single Responsibility: Handles only session state management
    - Domain Value Objects: Uses session identifiers and metadata
    - Ubiquitous Language: Method names reflect business concepts
    - Fail-Safe Security: Implements secure session validation and revocation
    """

    @abstractmethod
    async def create_session(self, user_id: int, jti: str, refresh_token_hash: str) -> None:
        """Creates and persists a new session record.

        Args:
            user_id: The ID of the user for whom the session is created.
            jti: The unique identifier (jti) of the initial JWT access token.
            refresh_token_hash: The hash of the associated refresh token.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_session(self, jti: str) -> Optional[dict]:
        """Retrieves a session by its JWT identifier (jti).

        Args:
            jti: The unique identifier of the session to retrieve.

        Returns:
            A dictionary representing the session, or `None` if not found.
        """
        raise NotImplementedError

    @abstractmethod
    async def revoke_session(self, jti: str) -> None:
        """Revokes a session, effectively logging the user out.

        This marks the session as revoked in the database, preventing any
        associated refresh tokens from being used.

        Args:
            jti: The unique identifier of the session to revoke.
        """
        raise NotImplementedError

    @abstractmethod
    async def is_session_valid(self, jti: str) -> bool:
        """Checks if a session is valid and not revoked.

        Args:
            jti: The unique identifier of the session to check.

        Returns:
            `True` if the session is valid, `False` otherwise.
        """
        raise NotImplementedError 