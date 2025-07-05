"""Unified email service interface for all email operations.

This module defines a comprehensive email service interface that handles
all email-related operations including password reset, email confirmation,
welcome emails, and notifications. It follows Domain-Driven Design principles
and provides a clean abstraction for email infrastructure.

Key DDD Principles Applied:
- Single Responsibility: Interface focuses only on email operations
- Ubiquitous Language: Method names reflect business domain concepts
- Dependency Inversion: Domain depends on abstractions, not concretions
- Interface Segregation: Clients depend only on methods they use
- Bounded Context: All email operations belong to the notification domain
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from src.domain.entities.user import User
from src.domain.value_objects.reset_token import ResetToken


class IEmailService(ABC):
    """Unified interface for all email operations following DDD principles.
    
    This interface provides a comprehensive contract for all email-related
    operations including password reset, email confirmation, welcome emails,
    and notifications. It abstracts away infrastructure concerns and provides
    a clean domain-focused API.
    
    DDD Principles:
    - Single Responsibility: Handles only email operations
    - Domain Value Objects: Uses domain entities and value objects
    - Ubiquitous Language: Method names reflect business concepts
    - Dependency Inversion: Abstracts external email infrastructure
    - Interface Segregation: Provides specific methods for each use case
    
    Security Features:
    - Rate limiting integration points
    - Secure template rendering
    - Audit logging support
    - Error handling standardization
    """

    @abstractmethod
    async def send_password_reset_email(
        self, 
        user: User, 
        token: ResetToken, 
        language: str = "en"
    ) -> bool:
        """Send password reset email to user.
        
        Args:
            user: User entity to send email to
            token: Reset token value object with expiration
            language: Language code for email localization
            
        Returns:
            bool: True if email sent successfully
            
        Raises:
            EmailServiceError: If email delivery fails
        """
        pass

    @abstractmethod
    async def send_email_confirmation_email(
        self,
        user: User,
        confirmation_token: str,
        language: str = "en"
    ) -> bool:
        """Send email confirmation email to user.
        
        Args:
            user: User entity to send email to
            confirmation_token: Email confirmation token
            language: Language code for email localization
            
        Returns:
            bool: True if email sent successfully
            
        Raises:
            EmailServiceError: If email delivery fails
        """
        pass

    @abstractmethod
    async def send_welcome_email(
        self,
        user: User,
        language: str = "en"
    ) -> bool:
        """Send welcome email to newly registered user.
        
        Args:
            user: User entity to send email to
            language: Language code for email localization
            
        Returns:
            bool: True if email sent successfully
            
        Raises:
            EmailServiceError: If email delivery fails
        """
        pass

    @abstractmethod
    async def send_notification_email(
        self,
        user: User,
        subject: str,
        template_name: str,
        context: Dict[str, Any],
        language: str = "en"
    ) -> bool:
        """Send generic notification email to user.
        
        Args:
            user: User entity to send email to
            subject: Email subject line
            template_name: Name of email template to use
            context: Template context variables
            language: Language code for email localization
            
        Returns:
            bool: True if email sent successfully
            
        Raises:
            EmailServiceError: If email delivery fails
        """
        pass

    @abstractmethod
    async def is_rate_limited(self, user_id: int, email_type: str) -> bool:
        """Check if user is rate limited for specific email type.
        
        Args:
            user_id: User ID to check rate limit for
            email_type: Type of email (e.g., 'password_reset', 'confirmation')
            
        Returns:
            bool: True if user is rate limited
        """
        pass

    @abstractmethod
    async def record_email_attempt(self, user_id: int, email_type: str) -> None:
        """Record email sending attempt for rate limiting.
        
        Args:
            user_id: User ID to record attempt for
            email_type: Type of email sent
        """
        pass

    @abstractmethod
    def get_supported_languages(self) -> list[str]:
        """Get list of supported languages for email templates.
        
        Returns:
            list[str]: List of supported language codes
        """
        pass

    @abstractmethod
    def is_test_mode(self) -> bool:
        """Check if email service is in test mode.
        
        Returns:
            bool: True if in test mode (emails logged instead of sent)
        """
        pass 