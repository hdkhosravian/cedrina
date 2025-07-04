"""Password reset service interfaces.

This module defines the password reset service interfaces following
Domain-Driven Design principles. These interfaces encapsulate the business
logic for password reset workflows, token management, and email notifications.

Key DDD Principles Applied:
- Single Responsibility: Each interface has one clear purpose
- Ubiquitous Language: Interface names reflect business domain concepts
- Dependency Inversion: Domain depends on abstractions, not concretions
- Bounded Context: All interfaces belong to the password reset domain
- Interface Segregation: Clients depend only on interfaces they use

Password Reset Domain Services:
- Password Reset Token Service: Secure token generation and validation
- Password Reset Email Service: Email notification and template rendering
"""

from abc import ABC, abstractmethod

from src.domain.entities.user import User
from src.domain.value_objects.reset_token import ResetToken


class IPasswordResetTokenService(ABC):
    """Interface for password reset token lifecycle management.
    
    This service is responsible for the entire lifecycle of a password reset
    token, from secure generation to validation and invalidation. It acts as
    a centralized authority for managing the state of password reset requests,
    ensuring they are handled securely and efficiently.
    
    DDD Principles:
    - Single Responsibility: Handles only password reset token operations
    - Domain Value Objects: Uses ResetToken value objects for validation
    - Ubiquitous Language: Method names reflect business concepts
    - Fail-Safe Security: Implements secure token generation and validation
    """

    @abstractmethod
    async def generate_token(self, user: User) -> ResetToken:
        """Generates a secure, unique password reset token for a user.

        This method should create a cryptographically strong token, associate it
        with the user, and set an expiration time. It should also enforce rate
        limiting to prevent abuse.

        Args:
            user: The `User` entity for whom to generate the token.

        Returns:
            A `ResetToken` value object containing the token and its metadata.

        Raises:
            RateLimitExceededError: If the user has requested too many tokens
                in a short period.
        """
        raise NotImplementedError

    @abstractmethod
    def validate_token(self, user: User, token: str) -> bool:
        """Validates a password reset token provided by a user.

        This method should compare the provided token against the stored token
        hash in a secure, constant-time manner to prevent timing attacks. It
        should also check for token expiration.

        Args:
            user: The `User` entity associated with the token.
            token: The raw password reset token from the user.

        Returns:
            `True` if the token is valid, `False` otherwise.
        """
        raise NotImplementedError

    @abstractmethod
    def invalidate_token(self, user: User, reason: str = "used") -> None:
        """Invalidates a user's password reset token.

        This should be called after a successful password reset to ensure the
        token cannot be reused.

        Args:
            user: The `User` entity whose token should be invalidated.
            reason: A string indicating why the token is being invalidated
                (e.g., "used", "expired").
        """
        raise NotImplementedError

    @abstractmethod
    def is_token_expired(self, user: User) -> bool:
        """Checks if a user's password reset token has expired.

        Args:
            user: The `User` entity to check.

        Returns:
            `True` if the token is expired, `False` otherwise.
        """
        raise NotImplementedError


class IPasswordResetEmailService(ABC):
    """Interface for password reset email notifications.
    
    This service acts as an abstraction over the external email sending
    mechanism. It defines a simple contract for sending a password reset email,
    allowing the domain logic to remain independent of the specific email
    provider or technology used in the infrastructure layer.
    
    DDD Principles:
    - Single Responsibility: Handles only password reset email operations
    - Domain Value Objects: Uses ResetToken value objects for validation
    - Ubiquitous Language: Method names reflect business concepts
    - Dependency Inversion: Abstracts external email infrastructure
    """

    @abstractmethod
    async def send_password_reset_email(
        self, user: User, token: ResetToken, language: str = "en"
    ) -> bool:
        """Sends a password reset email to the user.

        Args:
            user: The `User` entity to whom the email will be sent.
            token: The `ResetToken` to be included in the email link.
            language: The preferred language for the email template.

        Returns:
            `True` if the email was sent successfully, `False` otherwise.
        """
        raise NotImplementedError 