"""Security service interfaces for encryption and protection mechanisms.

This module defines the security service interfaces following Domain-Driven Design
principles. These interfaces encapsulate the business logic for password encryption,
rate limiting, and security protection mechanisms.

Key DDD Principles Applied:
- Single Responsibility: Each interface has one clear purpose
- Ubiquitous Language: Interface names reflect business domain concepts
- Dependency Inversion: Domain depends on abstractions, not concretions
- Bounded Context: All interfaces belong to the security domain
- Interface Segregation: Clients depend only on interfaces they use

Security Domain Services:
- Password Encryption Service: Defense-in-depth password hash encryption
- Rate Limiting Service: Protection against abuse and brute-force attacks
"""

from abc import ABC, abstractmethod
from typing import Optional


class IPasswordEncryptionService(ABC):
    """Interface for password hash encryption and decryption.
    
    This service provides a "defense-in-depth" security layer by applying
    symmetric encryption to already-hashed passwords. This means that even if
    the database is compromised, the password hashes are not immediately usable
    without access to the separate encryption key.
    
    DDD Principles:
    - Single Responsibility: Handles only password encryption operations
    - Domain Value Objects: Uses encrypted hash representations
    - Ubiquitous Language: Method names reflect security concepts
    - Fail-Safe Security: Implements secure encryption and decryption
    """

    @abstractmethod
    async def encrypt_password_hash(self, bcrypt_hash: str) -> str:
        """Encrypts a bcrypt password hash.

        Args:
            bcrypt_hash: The raw bcrypt hash string to be encrypted.

        Returns:
            The encrypted hash, typically as a base64-encoded string.
        """
        raise NotImplementedError

    @abstractmethod
    async def decrypt_password_hash(self, encrypted_hash: str) -> str:
        """Decrypts an encrypted password hash.

        Args:
            encrypted_hash: The encrypted hash string to be decrypted.

        Returns:
            The original raw bcrypt hash string.
        """
        raise NotImplementedError

    @abstractmethod
    def is_encrypted_format(self, value: str) -> bool:
        """Checks if a given string appears to be in the encrypted format.

        This can be used to determine if a stored password hash needs to be
        decrypted before verification.

        Args:
            value: The string to check.

        Returns:
            `True` if the string matches the expected encrypted format,
            `False` otherwise.
        """
        raise NotImplementedError


class IRateLimitingService(ABC):
    """Interface for rate limiting and abuse protection.
    
    This service provides a domain-centric way to check and enforce rate limits
    for specific actions, such as login attempts or password reset requests,
    protecting the system from abuse and brute-force attacks.
    
    DDD Principles:
    - Single Responsibility: Handles only rate limiting operations
    - Domain Value Objects: Uses rate limit configurations and time windows
    - Ubiquitous Language: Method names reflect protection concepts
    - Fail-Safe Security: Implements secure rate limiting with proper timeouts
    """

    @abstractmethod
    async def is_user_rate_limited(self, user_id: int, action: str) -> bool:
        """Checks if a user is currently rate-limited for a specific action.

        Args:
            user_id: The ID of the user to check.
            action: A string identifying the action being rate-limited (e.g., "login").

        Returns:
            `True` if the user is currently rate-limited, `False` otherwise.
        """
        raise NotImplementedError

    @abstractmethod
    async def record_attempt(self, user_id: int, action: str) -> None:
        """Records an attempt for a rate-limited action by a user.

        This method should be called each time a user performs an action that is
        subject to rate limiting.

        Args:
            user_id: The ID of the user performing the action.
            action: A string identifying the action.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_time_until_reset(self, user_id: int, action: str) -> Optional[int]:
        """Calculates the time remaining until a user's rate limit is reset.

        Args:
            user_id: The ID of the user to check.
            action: A string identifying the action.

        Returns:
            The number of seconds until the rate limit resets, or `None` if the
            user is not currently rate-limited.
        """
        raise NotImplementedError 