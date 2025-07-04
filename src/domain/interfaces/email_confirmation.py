"""Email confirmation service interface."""

from abc import ABC, abstractmethod
from typing import Optional

from src.domain.entities.user import User


class IEmailConfirmationService(ABC):
    """Interface for email confirmation service operations following DDD principles.
    
    This interface defines the contract for email confirmation functionality
    including token generation, email sending, and confirmation processing.
    """
    
    @abstractmethod
    async def send_confirmation_email(
        self,
        user: User,
        language: str = "en",
        correlation_id: str = "",
    ) -> str:
        """Send email confirmation to user.
        
        Args:
            user: User entity to send confirmation to
            language: Language code for email template
            correlation_id: Request correlation ID for tracking
            
        Returns:
            str: Confirmation token that was sent
            
        Raises:
            EmailConfirmationError: If email sending fails
        """
        pass
    
    @abstractmethod
    async def confirm_email(
        self,
        token: str,
        correlation_id: str = "",
    ) -> User:
        """Confirm user email with token.
        
        Args:
            token: Email confirmation token
            correlation_id: Request correlation ID for tracking
            
        Returns:
            User: Confirmed user entity
            
        Raises:
            EmailConfirmationError: If token is invalid or expired
        """
        pass
    
    @abstractmethod
    async def resend_confirmation_email(
        self,
        email: str,
        language: str = "en",
        correlation_id: str = "",
    ) -> bool:
        """Resend confirmation email to user.
        
        Args:
            email: Email address to resend confirmation to
            language: Language code for email template
            correlation_id: Request correlation ID for tracking
            
        Returns:
            bool: True if email was sent successfully
            
        Raises:
            EmailConfirmationError: If email sending fails
        """
        pass
    
    @abstractmethod
    async def generate_confirmation_token(self, user: User) -> str:
        """Generate a new confirmation token for user.
        
        Args:
            user: User entity to generate token for
            
        Returns:
            str: Generated confirmation token
        """
        pass
    
    @abstractmethod
    async def is_confirmation_required(self) -> bool:
        """Check if email confirmation is required based on settings.
        
        Returns:
            bool: True if email confirmation is enabled
        """
        pass