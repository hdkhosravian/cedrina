"""Password Reset Email Service.

This service handles the specific business logic for sending password reset emails,
separating it from the generic email service to maintain clean separation of concerns.
"""

from typing import Optional
from urllib.parse import urlencode
from structlog import get_logger

from src.core.config.email import EmailSettings
from src.core.exceptions import EmailServiceError, TemplateRenderError
from src.domain.entities.user import User
from src.domain.services.email.email_service import EmailService
from src.utils.i18n import get_translated_message

logger = get_logger(__name__)


class PasswordResetEmailService:
    """Service for sending password reset emails.
    
    This service handles the specific business logic for password reset emails,
    including template selection, context preparation, and URL building.
    """
    
    def __init__(self, email_service: EmailService, settings: EmailSettings):
        """Initialize PasswordResetEmailService.
        
        Args:
            email_service: Generic email service for sending emails
            settings: Email configuration settings
        """
        self.email_service = email_service
        self.settings = settings
        
        logger.info("PasswordResetEmailService initialized")
    
    async def send_password_reset_email(
        self,
        user: User,
        token: str,
        language: str = "en"
    ) -> bool:
        """Send password reset email to user.
        
        Args:
            user: User entity requesting password reset
            token: Secure reset token
            language: Language code for i18n
            
        Returns:
            bool: True if email sent successfully
            
        Raises:
            EmailServiceError: If email sending fails
            
        Security:
            - Token is included in secure URL
            - Templates are safely rendered
            - User data is validated
        """
        try:
            # Build reset URL with token
            reset_url = self._build_reset_url(token)
            
            # Prepare template context
            context = {
                'user': user,
                'reset_url': reset_url,
                'token': token,
                'expire_minutes': self.settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES,
                'app_name': self.settings.FROM_NAME,
                'language': language
            }
            
            # Render HTML template
            try:
                html_content = self.email_service.render_template(
                    f'password_reset_{language}.html',
                    **context
                )
            except TemplateRenderError:
                # Fallback to English if language-specific template not found
                html_content = self.email_service.render_template(
                    'password_reset_en.html',
                    **context
                )
            
            # Render text template
            try:
                text_content = self.email_service.render_template(
                    f'password_reset_{language}.txt',
                    **context
                )
            except TemplateRenderError:
                # Fallback to English if language-specific template not found
                text_content = self.email_service.render_template(
                    'password_reset_en.txt',
                    **context
                )
            
            # Get translated subject
            subject = get_translated_message("password_reset_email_subject", language)
            
            # Send email
            success = await self.email_service.send_email(
                to_email=user.email,
                subject=subject,
                html_content=html_content,
                text_content=text_content
            )
            
            logger.info(
                "Password reset email sent",
                user_id=user.id,
                username=user.username,
                email=user.email,
                language=language
            )
            
            return success
            
        except TemplateRenderError as e:
            logger.error(
                "Failed to render password reset email template",
                user_id=user.id,
                language=language,
                error=str(e)
            )
            raise EmailServiceError(f"Failed to render password reset email template: {e}")
            
        except Exception as e:
            logger.error(
                "Failed to send password reset email",
                user_id=user.id,
                username=user.username,
                error=str(e)
            )
            raise EmailServiceError(f"Failed to send password reset email: {e}")
    
    def _build_reset_url(self, token: str) -> str:
        """Build password reset URL with token.
        
        Args:
            token: Reset token
            
        Returns:
            str: Complete reset URL
        """
        base_url = self.settings.PASSWORD_RESET_URL_BASE
        params = {'token': token}
        query_string = urlencode(params)
        
        return f"{base_url}?{query_string}" 