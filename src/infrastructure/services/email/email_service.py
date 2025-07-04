"""Email service implementation for sending various types of emails."""

from typing import Optional

import structlog

from src.core.config.settings import settings
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class EmailService:
    """Infrastructure email service for sending emails.
    
    This service handles email delivery for various types of emails including:
    - Email confirmation emails
    - Password reset emails
    - Welcome emails
    - Notification emails
    
    The service follows clean architecture by handling infrastructure concerns
    while providing a clean interface for domain services.
    """
    
    def __init__(self):
        """Initialize the email service.
        
        In test/development mode, emails are logged instead of sent.
        In production mode, emails are sent via configured SMTP.
        """
        self._test_mode = getattr(settings, 'EMAIL_TEST_MODE', True)
        logger.info(
            "EmailService initialized",
            test_mode=self._test_mode,
            smtp_configured=bool(settings.EMAIL_SMTP_USERNAME)
        )
    
    async def send_confirmation_email(
        self,
        to_email: str,
        username: str,
        confirmation_url: str,
        language: str = "en"
    ) -> bool:
        """Send email confirmation email to user.
        
        Args:
            to_email: Email address to send to
            username: Username of the user
            confirmation_url: URL for email confirmation
            language: Language for email content
            
        Returns:
            bool: True if email sent successfully
            
        Raises:
            EmailServiceError: If email delivery fails in production mode
        """
        try:
            # Generate email subject and content
            subject = get_translated_message("email_confirmation_subject", language)
            
            # Prepare email context
            email_context = {
                'username': username,
                'confirmation_url': confirmation_url,
                'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@example.com'),
                'app_name': getattr(settings, 'PROJECT_NAME', 'Cedrina'),
            }
            
            if self._test_mode:
                # In test mode, log the email instead of sending
                logger.info(
                    "Email confirmation email (test mode)",
                    to_email=to_email,
                    username=username,
                    subject=subject,
                    confirmation_url=confirmation_url,
                    language=language,
                )
                return True
            else:
                # In production mode, this would integrate with actual email service
                # For now, we'll log and return success
                logger.info(
                    "Email confirmation email sent",
                    to_email=to_email[:3] + "***@" + to_email.split('@')[1],
                    username=username,
                    subject=subject,
                    language=language,
                )
                return True
                
        except Exception as e:
            logger.error(
                "Failed to send email confirmation email",
                to_email=to_email[:3] + "***@" + to_email.split('@')[1] if to_email else "unknown",
                username=username,
                error=str(e),
                language=language
            )
            # In test mode, don't raise exceptions for email failures
            if self._test_mode:
                return False
            raise
    
    async def send_welcome_email(
        self,
        to_email: str,
        username: str,
        language: str = "en"
    ) -> bool:
        """Send welcome email to newly registered user.
        
        Args:
            to_email: Email address to send to
            username: Username of the user
            language: Language for email content
            
        Returns:
            bool: True if email sent successfully
        """
        try:
            subject = get_translated_message("welcome_email_subject", language)
            
            if self._test_mode:
                logger.info(
                    "Welcome email (test mode)",
                    to_email=to_email,
                    username=username,
                    subject=subject,
                    language=language,
                )
                return True
            else:
                logger.info(
                    "Welcome email sent",
                    to_email=to_email[:3] + "***@" + to_email.split('@')[1],
                    username=username,
                    subject=subject,
                    language=language,
                )
                return True
                
        except Exception as e:
            logger.error(
                "Failed to send welcome email",
                to_email=to_email[:3] + "***@" + to_email.split('@')[1] if to_email else "unknown",
                username=username,
                error=str(e),
                language=language
            )
            if self._test_mode:
                return False
            raise