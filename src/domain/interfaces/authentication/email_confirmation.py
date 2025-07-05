"""Email confirmation service interfaces.

This module defines the email confirmation service interfaces following
Domain-Driven Design principles. These interfaces encapsulate the business
logic for email confirmation workflows, token management, and email notifications.

Key DDD Principles Applied:
- Single Responsibility: Each interface has one clear purpose
- Ubiquitous Language: Interface names reflect business domain concepts
- Dependency Inversion: Domain depends on abstractions, not concretions
- Bounded Context: All interfaces belong to the email confirmation domain
- Interface Segregation: Clients depend only on interfaces they use

Email Confirmation Domain Services:
- Email Confirmation Token Service: Secure token generation and validation
- Email Confirmation Email Service: Email notification and template rendering
- Email Confirmation Service: Core confirmation workflow management
"""

from abc import ABC, abstractmethod

from src.domain.entities.user import User
from src.domain.value_objects.email_confirmation_token import EmailConfirmationToken


class IEmailConfirmationTokenService(ABC):
    """Interface for email confirmation token lifecycle management.
    
    This service is responsible for the entire lifecycle of an email confirmation
    token, from secure generation to validation and invalidation. It acts as
    a centralized authority for managing the state of email confirmation requests,
    ensuring they are handled securely and efficiently.
    
    DDD Principles:
    - Single Responsibility: Handles only email confirmation token operations
    - Domain Value Objects: Uses EmailConfirmationToken value objects for validation
    - Ubiquitous Language: Method names reflect business concepts
    - Fail-Safe Security: Implements secure token generation and validation
    """

    @abstractmethod
    async def generate_token(self, user: User) -> EmailConfirmationToken:
        """Generates a secure, unique email confirmation token for a user.

        This method should create a cryptographically strong token, associate it
        with the user, and store it for later validation. Email confirmation tokens
        do not expire.

        Args:
            user: The `User` entity for whom to generate the token.

        Returns:
            An `EmailConfirmationToken` value object containing the token and its metadata.

        Raises:
            RateLimitExceededError: If the user has requested too many tokens
                in a short period.
        """
        raise NotImplementedError

    @abstractmethod
    def validate_token(self, user: User, token: str) -> bool:
        """Validates an email confirmation token provided by a user.

        This method should compare the provided token against the stored token
        hash in a secure, constant-time manner to prevent timing attacks.

        Args:
            user: The `User` entity associated with the token.
            token: The raw email confirmation token from the user.

        Returns:
            `True` if the token is valid, `False` otherwise.
        """
        raise NotImplementedError

    @abstractmethod
    def invalidate_token(self, user: User, reason: str = "confirmed") -> None:
        """Invalidates a user's email confirmation token.

        This should be called after a successful email confirmation to ensure the
        token cannot be reused.

        Args:
            user: The `User` entity whose token should be invalidated.
            reason: A string indicating why the token is being invalidated
                (e.g., "confirmed", "expired").
        """
        raise NotImplementedError

    @abstractmethod
    def has_active_token(self, user: User) -> bool:
        """Checks if a user has an active email confirmation token.

        Args:
            user: The `User` entity to check.

        Returns:
            `True` if the user has an active token, `False` otherwise.
        """
        raise NotImplementedError


class IEmailConfirmationEmailService(ABC):
    """Interface for email confirmation email notifications.
    
    This service acts as an abstraction over the external email sending
    mechanism. It defines a simple contract for sending an email confirmation email,
    allowing the domain logic to remain independent of the specific email
    provider or technology used in the infrastructure layer.
    
    DDD Principles:
    - Single Responsibility: Handles only email confirmation email operations
    - Domain Value Objects: Uses EmailConfirmationToken value objects for validation
    - Ubiquitous Language: Method names reflect business concepts
    - Dependency Inversion: Abstracts external email infrastructure
    """

    @abstractmethod
    async def send_email_confirmation_email(
        self, user: User, token: EmailConfirmationToken, language: str = "en"
    ) -> bool:
        """Sends an email confirmation email to the user.

        Args:
            user: The `User` entity to whom the email will be sent.
            token: The `EmailConfirmationToken` to be included in the email link.
            language: The preferred language for the email template.

        Returns:
            `True` if the email was sent successfully, `False` otherwise.
        """
        raise NotImplementedError


class IEmailConfirmationService(ABC):
    """Interface for email confirmation workflow management.
    
    This service orchestrates the complete email confirmation workflow,
    including token generation, email sending, and confirmation validation.
    It acts as the primary entry point for email confirmation operations.
    
    DDD Principles:
    - Single Responsibility: Handles only email confirmation workflow
    - Domain Value Objects: Uses EmailConfirmationToken value objects
    - Ubiquitous Language: Method names reflect business concepts
    - Domain Events: Publishes confirmation events for audit trails
    """

    @abstractmethod
    async def send_confirmation_email(
        self, user: User, language: str = "en"
    ) -> bool:
        """Sends a confirmation email to the user.

        This method generates a new confirmation token and sends an email
        with a confirmation link.

        Args:
            user: The `User` entity to send confirmation email to.
            language: The preferred language for the email template.

        Returns:
            `True` if the confirmation email was sent successfully, `False` otherwise.

        Raises:
            RateLimitExceededError: If too many confirmation emails have been sent.
            EmailServiceError: If email delivery fails.
        """
        raise NotImplementedError

    @abstractmethod
    async def confirm_email(
        self, token: str, language: str = "en"
    ) -> User:
        """Confirms a user's email address using a valid token.

        This method validates the confirmation token and activates the user's
        account if the token is valid.

        Args:
            token: The email confirmation token from the user.
            language: The preferred language for error messages.

        Returns:
            The confirmed `User` entity.

        Raises:
            EmailConfirmationError: If the token is invalid or confirmation fails.
            UserNotFoundError: If the user associated with the token is not found.
        """
        raise NotImplementedError

    @abstractmethod
    async def resend_confirmation_email(
        self, email: str, language: str = "en"
    ) -> bool:
        """Resends a confirmation email to the user.

        This method generates a new confirmation token and sends a fresh
        confirmation email, invalidating any previous tokens.

        Args:
            email: The email address of the user.
            language: The preferred language for the email template.

        Returns:
            `True` if the confirmation email was sent successfully, `False` otherwise.

        Raises:
            UserNotFoundError: If no user is found with the provided email.
            RateLimitExceededError: If too many confirmation emails have been sent.
            EmailServiceError: If email delivery fails.
        """
        raise NotImplementedError 