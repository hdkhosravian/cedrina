"""Email Confirmation Domain Service.

This service handles email confirmation operations following Domain-Driven Design
principles and single responsibility principle.
"""

from datetime import datetime, timezone
from typing import Optional

import structlog

from src.core.exceptions import EmailConfirmationError, UserNotFoundError
from src.domain.entities.user import User
from src.domain.events.email_confirmation_events import (
    EmailConfirmationCompletedEvent,
    EmailConfirmationFailedEvent,
    EmailConfirmationRequestedEvent,
)
from src.domain.interfaces.repositories import IUserRepository
from src.domain.interfaces import (
    IEventPublisher,
    IEmailConfirmationService,
    IEmailConfirmationTokenService,
    IEmailConfirmationEmailService,
)
from src.domain.value_objects.email_confirmation_token import EmailConfirmationToken
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class EmailConfirmationService(IEmailConfirmationService):
    """Domain service for email confirmation operations.
    
    This service handles only email confirmation-related operations,
    following the single responsibility principle from clean architecture.
    
    Responsibilities:
    - Send confirmation emails with tokens
    - Confirm email addresses using tokens
    - Resend confirmation emails
    - Publish confirmation events
    - Enforce business rules for confirmation
    
    Security Features:
    - Secure token generation and validation
    - Rate limiting for email sending
    - Comprehensive audit logging via domain events
    - Token invalidation after use
    """
    
    def __init__(
        self,
        user_repository: IUserRepository,
        token_service: IEmailConfirmationTokenService,
        email_service: IEmailConfirmationEmailService,
        event_publisher: IEventPublisher,
    ):
        """Initialize email confirmation service with dependencies.
        
        Args:
            user_repository: Repository for user data access
            token_service: Service for token generation and validation
            email_service: Service for email sending
            event_publisher: Publisher for domain events
        """
        self._user_repository = user_repository
        self._token_service = token_service
        self._email_service = email_service
        self._event_publisher = event_publisher
        
        logger.info("EmailConfirmationService initialized")
    
    async def send_confirmation_email(
        self, user: User, language: str = "en"
    ) -> bool:
        """Send confirmation email to user.
        
        Args:
            user: User entity to send confirmation email to
            language: Language code for I18N
            
        Returns:
            bool: True if email sent successfully
            
        Raises:
            EmailConfirmationError: If email delivery fails
        """
        try:
            logger.info(
                "Sending email confirmation",
                user_id=user.id,
                email=user.email[:3] + "***@" + user.email.split('@')[1],
                language=language
            )
            
            # Generate confirmation token
            token = await self._token_service.generate_token(user)
            
            # Update user with token
            await self._update_user_with_token(user, token)
            
            # Send confirmation email
            await self._send_confirmation_email(user, token, language)
            
            # Publish confirmation requested event
            await self._publish_confirmation_requested_event(
                user, "email", language
            )
            
            logger.info(
                "Email confirmation sent successfully",
                user_id=user.id,
                email=user.email[:3] + "***@" + user.email.split('@')[1],
                language=language
            )
            
            return True
            
        except Exception as e:
            logger.error(
                "Failed to send email confirmation",
                user_id=user.id,
                error=str(e),
                language=language
            )
            raise EmailConfirmationError(
                get_translated_message("email_confirmation_send_failed", language)
            ) from e
    
    async def confirm_email(
        self, token: str, language: str = "en"
    ) -> User:
        """Confirm user email using token.
        
        Args:
            token: Email confirmation token
            language: Language code for error messages
            
        Returns:
            User: Confirmed user entity
            
        Raises:
            EmailConfirmationError: If token is invalid or confirmation fails
            UserNotFoundError: If user associated with token is not found
        """
        user: Optional[User] = None
        
        try:
            logger.info(
                "Processing email confirmation",
                token_prefix=token[:8] if token else "none"
            )
            
            # Validate token format and find user
            user = await self._validate_token_and_get_user(token, language)
            
            # Validate token against user record
            await self._validate_token_against_user(user, token, language)
            
            # Confirm user email and activate account
            await self._confirm_user_email(user)
            
            # Invalidate token after successful confirmation
            self._token_service.invalidate_token(user, reason="email_confirmed")
            await self._user_repository.save(user)
            
            # Publish success event
            await self._publish_confirmation_completed_event(user, language)
            
            logger.info(
                "Email confirmation completed successfully",
                user_id=user.id,
                email=user.email[:3] + "***@" + user.email.split('@')[1]
            )
            
            return user
            
        except (EmailConfirmationError, UserNotFoundError):
            # Re-raise known domain exceptions
            if user:
                await self._publish_confirmation_failed_event(
                    user, "token_validation_failed", token[:8] if token else None, language
                )
            raise
        except Exception as e:
            # Handle unexpected errors
            logger.error(
                "Unexpected error during email confirmation",
                token_prefix=token[:8] if token else "none",
                error=str(e)
            )
            
            if user:
                await self._publish_confirmation_failed_event(
                    user, "system_error", token[:8] if token else None, language
                )
            
            raise EmailConfirmationError(
                get_translated_message("email_confirmation_system_error", language)
            ) from e
    
    async def resend_confirmation_email(
        self, email: str, language: str = "en"
    ) -> bool:
        """Resend confirmation email to user.
        
        Args:
            email: Email address of the user
            language: Language code for I18N
            
        Returns:
            bool: True if email sent successfully
            
        Raises:
            UserNotFoundError: If no user is found with the provided email
            EmailConfirmationError: If email delivery fails
        """
        try:
            logger.info(
                "Resending email confirmation",
                email=email[:3] + "***@" + email.split('@')[1],
                language=language
            )
            
            # Find user by email
            user = await self._user_repository.get_by_email(email)
            if not user:
                logger.warning(
                    "Resend confirmation attempted for unknown email",
                    email=email[:3] + "***@" + email.split('@')[1]
                )
                raise UserNotFoundError(
                    get_translated_message("user_not_found", language)
                )
            
            # Check if user needs confirmation
            if user.email_confirmed:
                logger.info(
                    "Resend confirmation skipped - email already confirmed",
                    user_id=user.id,
                    email=email[:3] + "***@" + email.split('@')[1]
                )
                return True
            
            # Generate new confirmation token (invalidates previous)
            token = await self._token_service.generate_token(user)
            
            # Update user with new token
            await self._update_user_with_token(user, token)
            
            # Send confirmation email
            await self._send_confirmation_email(user, token, language)
            
            # Publish confirmation requested event
            await self._publish_confirmation_requested_event(
                user, "resend", language
            )
            
            logger.info(
                "Email confirmation resent successfully",
                user_id=user.id,
                email=email[:3] + "***@" + email.split('@')[1],
                language=language
            )
            
            return True
            
        except UserNotFoundError:
            # Re-raise user not found exception
            raise
        except Exception as e:
            logger.error(
                "Failed to resend email confirmation",
                email=email[:3] + "***@" + email.split('@')[1],
                error=str(e),
                language=language
            )
            raise EmailConfirmationError(
                get_translated_message("email_confirmation_resend_failed", language)
            ) from e
    
    async def _validate_token_and_get_user(
        self, token: str, language: str
    ) -> User:
        """Validate token format and find associated user.
        
        Args:
            token: Token to validate and lookup
            language: Language for error messages
            
        Returns:
            User: User entity associated with token
            
        Raises:
            EmailConfirmationError: If token format is invalid or user not found
        """
        # Validate token format using value object
        try:
            # This will raise ValueError if format is invalid
            EmailConfirmationToken.from_existing(token, datetime.now(timezone.utc))
        except ValueError:
            logger.warning("Invalid email confirmation token format received")
            raise EmailConfirmationError(
                get_translated_message("email_confirmation_token_invalid", language)
            )
        
        # Find user by token
        user = await self._user_repository.get_by_email_confirmation_token(token)
        if not user:
            logger.warning(
                "Email confirmation attempted with unknown token",
                token_prefix=token[:8]
            )
            raise EmailConfirmationError(
                get_translated_message("email_confirmation_token_invalid", language)
            )
        
        return user
    
    async def _validate_token_against_user(
        self, user: User, token: str, language: str
    ) -> None:
        """Validate token against user's stored token.
        
        Args:
            user: User entity with stored token
            token: Token to validate
            language: Language for error messages
            
        Raises:
            EmailConfirmationError: If token is invalid
        """
        if not self._token_service.validate_token(user, token):
            logger.warning(
                "Invalid email confirmation token",
                user_id=user.id,
                token_prefix=token[:8]
            )
            
            # Clear invalid token
            self._token_service.invalidate_token(user, reason="invalid_token_attempt")
            await self._user_repository.save(user)
            
            raise EmailConfirmationError(
                get_translated_message("email_confirmation_token_invalid", language)
            )
    
    async def _confirm_user_email(self, user: User) -> None:
        """Confirm user email and activate account.
        
        Args:
            user: User entity to confirm
        """
        user.email_confirmed = True
        user.is_active = True  # Activate account upon email confirmation
        await self._user_repository.save(user)
    
    async def _update_user_with_token(self, user: User, token: EmailConfirmationToken) -> None:
        """Update user entity with new confirmation token.
        
        Args:
            user: User entity to update
            token: Confirmation token to set
        """
        user.email_confirmation_token = token.value
        await self._user_repository.save(user)
    
    async def _send_confirmation_email(
        self, user: User, token: EmailConfirmationToken, language: str
    ) -> None:
        """Send confirmation email to user.
        
        Args:
            user: User to send email to
            token: Confirmation token to include
            language: Language for email content
            
        Raises:
            EmailConfirmationError: If email delivery fails
        """
        try:
            success = await self._email_service.send_email_confirmation_email(
                user=user,
                token=token,
                language=language,
            )
            
            if not success:
                raise EmailConfirmationError("Email delivery returned failure status")
                
        except Exception as e:
            logger.error(
                "Failed to send email confirmation email",
                user_id=user.id,
                error=str(e)
            )
            raise EmailConfirmationError(
                get_translated_message("email_confirmation_email_failed", language)
            ) from e
    
    async def _publish_confirmation_requested_event(
        self, user: User, method: str, language: str
    ) -> None:
        """Publish email confirmation requested event.
        
        Args:
            user: User entity
            method: Confirmation method (email, resend)
            language: Language for logging
        """
        try:
            event = EmailConfirmationRequestedEvent.create(
                user_id=user.id,
                email=user.email,
                confirmation_method=method,
            )
            
            await self._event_publisher.publish(event)
            
            logger.info(
                "Email confirmation requested event published",
                user_id=user.id,
                method=method
            )
            
        except Exception as e:
            logger.error(
                "Failed to publish email confirmation requested event",
                user_id=user.id,
                error=str(e)
            )
    
    async def _publish_confirmation_completed_event(
        self, user: User, language: str
    ) -> None:
        """Publish email confirmation completed event.
        
        Args:
            user: User entity
            language: Language for logging
        """
        try:
            event = EmailConfirmationCompletedEvent.create(
                user_id=user.id,
                email=user.email,
                confirmation_method="token",
            )
            
            await self._event_publisher.publish(event)
            
            logger.info(
                "Email confirmation completed event published",
                user_id=user.id
            )
            
        except Exception as e:
            logger.error(
                "Failed to publish email confirmation completed event",
                user_id=user.id,
                error=str(e)
            )
    
    async def _publish_confirmation_failed_event(
        self, user: User, failure_reason: str, token_prefix: Optional[str], language: str
    ) -> None:
        """Publish email confirmation failed event.
        
        Args:
            user: User entity
            failure_reason: Reason for failure
            token_prefix: Token prefix for logging
            language: Language for logging
        """
        try:
            event = EmailConfirmationFailedEvent.create(
                user_id=user.id,
                email=user.email,
                failure_reason=failure_reason,
                confirmation_method="token",
            )
            
            await self._event_publisher.publish(event)
            
            logger.info(
                "Email confirmation failed event published",
                user_id=user.id,
                failure_reason=failure_reason,
                token_prefix=token_prefix
            )
            
        except Exception as e:
            logger.error(
                "Failed to publish email confirmation failed event",
                user_id=user.id,
                error=str(e)
            ) 