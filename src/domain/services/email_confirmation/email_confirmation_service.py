"""Email confirmation domain service implementation."""

import secrets
from datetime import datetime, timezone
from typing import Optional

import structlog

from src.core.config.settings import settings
from src.core.exceptions import AuthenticationError
from src.domain.entities.user import User
from src.domain.interfaces.email_confirmation import IEmailConfirmationService
from src.domain.interfaces.repositories import IUserRepository
from src.domain.interfaces.infrastructure import IEventPublisher
from src.infrastructure.services.email.email_service import EmailService
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class EmailConfirmationService(IEmailConfirmationService):
    """Domain service for email confirmation operations following DDD principles.
    
    This service handles all email confirmation business logic including:
    - Token generation and validation
    - Email sending with proper templates
    - User confirmation processing
    - Domain event publishing
    """
    
    def __init__(
        self,
        user_repository: IUserRepository,
        event_publisher: IEventPublisher,
        email_service: EmailService,
    ):
        """Initialize email confirmation service with dependencies.
        
        Args:
            user_repository: Repository for user data access
            event_publisher: Publisher for domain events
            email_service: Service for sending emails
        """
        self._user_repository = user_repository
        self._event_publisher = event_publisher
        self._email_service = email_service
        
        logger.info(
            "EmailConfirmationService initialized",
            service_type="domain_service",
            responsibilities=["email_confirmation", "token_generation", "email_sending"]
        )
    
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
            AuthenticationError: If email sending fails
        """
        try:
            # Generate confirmation token
            token = await self.generate_confirmation_token(user)
            
            # Update user with confirmation token
            user.email_confirmation_token = token
            await self._user_repository.update(user)
            
            # Prepare email content
            confirmation_url = f"{settings.PASSWORD_RESET_URL_BASE}/confirm-email?token={token}"
            
            # Send confirmation email
            await self._email_service.send_confirmation_email(
                to_email=user.email,
                username=user.username,
                confirmation_url=confirmation_url,
                language=language,
            )
            
            logger.info(
                "Email confirmation sent successfully",
                user_id=user.id,
                email_masked=user.email[:3] + "***" + user.email[-3:],
                correlation_id=correlation_id,
            )
            
            return token
            
        except Exception as e:
            logger.error(
                "Failed to send confirmation email",
                user_id=user.id,
                error=str(e),
                correlation_id=correlation_id,
            )
            raise AuthenticationError(
                get_translated_message("email_confirmation_send_failed", language)
            )
    
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
            AuthenticationError: If token is invalid or expired
        """
        try:
            # Find user by confirmation token
            user = await self._user_repository.get_by_email_confirmation_token(token)
            
            if not user:
                logger.warning(
                    "Invalid email confirmation token",
                    token_length=len(token),
                    correlation_id=correlation_id,
                )
                raise AuthenticationError(
                    get_translated_message("invalid_email_confirmation_token", "en")
                )
            
            # Mark email as confirmed
            user.email_confirmed = True
            user.email_confirmed_at = datetime.now(timezone.utc)
            user.email_confirmation_token = None
            
            # If email confirmation is enabled, activate the user
            if settings.EMAIL_CONFIRMATION_ENABLED:
                user.is_active = True
            
            await self._user_repository.update(user)
            
            logger.info(
                "Email confirmed successfully",
                user_id=user.id,
                email_masked=user.email[:3] + "***" + user.email[-3:],
                correlation_id=correlation_id,
            )
            
            return user
            
        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(
                "Failed to confirm email",
                error=str(e),
                correlation_id=correlation_id,
            )
            raise AuthenticationError(
                get_translated_message("email_confirmation_failed", "en")
            )
    
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
            AuthenticationError: If email sending fails
        """
        try:
            # Find user by email
            user = await self._user_repository.get_by_email(email)
            
            if not user:
                # Don't reveal if email exists (security measure)
                logger.warning(
                    "Resend confirmation attempted for non-existent email",
                    email_masked=email[:3] + "***" + email[-3:],
                    correlation_id=correlation_id,
                )
                return True  # Return success to prevent email enumeration
            
            # Check if email is already confirmed
            if user.email_confirmed:
                logger.info(
                    "Resend confirmation attempted for already confirmed email",
                    user_id=user.id,
                    correlation_id=correlation_id,
                )
                return True
            
            # Send confirmation email
            await self.send_confirmation_email(user, language, correlation_id)
            
            return True
            
        except Exception as e:
            logger.error(
                "Failed to resend confirmation email",
                error=str(e),
                correlation_id=correlation_id,
            )
            raise AuthenticationError(
                get_translated_message("email_confirmation_resend_failed", language)
            )
    
    async def generate_confirmation_token(self, user: User) -> str:
        """Generate a new confirmation token for user.
        
        Args:
            user: User entity to generate token for
            
        Returns:
            str: Generated confirmation token
        """
        # Generate a secure random token
        token = secrets.token_urlsafe(32)  # 32 bytes = 256 bits of entropy
        
        logger.debug(
            "Generated confirmation token",
            user_id=user.id,
            token_length=len(token),
        )
        
        return token
    
    async def is_confirmation_required(self) -> bool:
        """Check if email confirmation is required based on settings.
        
        Returns:
            bool: True if email confirmation is enabled
        """
        return settings.EMAIL_CONFIRMATION_ENABLED