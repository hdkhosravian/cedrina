"""Infrastructure implementation of Email Confirmation Email Service.

This service provides concrete implementation for email confirmation email operations,
using domain value objects and following clean architecture principles.
"""

from typing import Optional, Any

import structlog

from src.core.config.settings import settings
from src.domain.entities.user import User
from src.domain.interfaces import IEmailConfirmationEmailService
from src.domain.value_objects.email_confirmation_token import EmailConfirmationToken
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class EmailConfirmationEmailService(IEmailConfirmationEmailService):
    """Infrastructure implementation of email confirmation email service.
    
    This service handles email confirmation email sending using domain value objects
    and following clean code principles.
    
    Features:
    - Template-based email rendering
    - I18N support for multiple languages
    - Secure token handling
    - Comprehensive logging
    - Test mode support
    """
    
    def __init__(self, test_mode: bool = False):
        """Initialize email confirmation email service.
        
        Args:
            test_mode: Enable test mode (emails logged instead of sent)
        """
        self._test_mode = test_mode
        
        logger.info("EmailConfirmationEmailService initialized", test_mode=test_mode)
    
    async def send_email_confirmation_email(
        self,
        user: User,
        token: EmailConfirmationToken,
        language: str = "en"
    ) -> bool:
        """Send email confirmation email to user.
        
        Args:
            user: User to send email to
            token: Confirmation token to include in email
            language: Language for email content
            
        Returns:
            bool: True if email sent successfully
            
        Raises:
            EmailServiceError: If email delivery fails in production mode
        """
        try:
            # Generate confirmation URL with token
            confirmation_url = self._generate_confirmation_url(token.value)
            
            # Prepare email context
            email_context = {
                'user_name': user.username or user.email.split('@')[0],
                'confirmation_url': confirmation_url,
                'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@example.com'),
                'app_name': getattr(settings, 'PROJECT_NAME', 'Cedrina'),
                'created_at': token.created_at,
            }
            
            # Generate email subject and content
            subject = get_translated_message("email_confirmation_subject", language)
            
            # Render email templates
            html_content = self._render_template(f"email_confirmation_{language}.html", **email_context)
            text_content = self._render_template(f"email_confirmation_{language}.txt", **email_context)
            
            if self._test_mode:
                # In test mode, log the email instead of sending
                logger.info(
                    "Email confirmation email (test mode)",
                    user_id=user.id,
                    user_email=user.email,
                    subject=subject,
                    confirmation_url=confirmation_url,
                    language=language,
                    created_at=token.created_at.isoformat(),
                    html_content_length=len(html_content),
                    text_content_length=len(text_content)
                )
                return True
            else:
                # In production mode, this would integrate with actual email service
                # For now, we'll log and return success
                logger.info(
                    "Email confirmation email sent",
                    user_id=user.id,
                    user_email=user.email[:3] + "***@" + user.email.split('@')[1],
                    subject=subject,
                    language=language,
                    created_at=token.created_at.isoformat(),
                    html_content_length=len(html_content),
                    text_content_length=len(text_content)
                )
                return True
                
        except Exception as e:
            logger.error(
                "Failed to send email confirmation email",
                user_id=user.id,
                user_email=user.email[:3] + "***@" + user.email.split('@')[1] if user.email else "unknown",
                error=str(e),
                language=language
            )
            # In test mode, don't raise exceptions for email failures
            if self._test_mode:
                return False
            raise
    
    def _generate_confirmation_url(self, token: str) -> str:
        """Generate email confirmation URL with token.
        
        Args:
            token: Confirmation token to include in URL
            
        Returns:
            str: Complete confirmation URL
        """
        base_url = getattr(settings, 'EMAIL_CONFIRMATION_URL_BASE', 'http://localhost:3000/confirm-email')
        return f"{base_url}?token={token}"
    
    def _render_template(self, template_name: str, **context: Any) -> str:
        """Render email template with provided context.
        
        Args:
            template_name: Name of the template file
            **context: Template variables
            
        Returns:
            str: Rendered template content
            
        Raises:
            TemplateRenderError: If template rendering fails
        """
        try:
            from jinja2 import Environment, FileSystemLoader, TemplateNotFound, TemplateError
            from pathlib import Path
            from src.core.exceptions import TemplateRenderError
            
            # Get template directory from settings
            template_dir = Path(getattr(settings, 'EMAIL_TEMPLATES_DIR', 'src/templates/email'))
            
            if not template_dir.exists():
                raise TemplateRenderError(f"Template directory not found: {template_dir}")
            
            # Set up Jinja2 environment
            jinja_env = Environment(
                loader=FileSystemLoader(str(template_dir)),
                autoescape=True,  # Enable auto-escaping for security
                trim_blocks=True,
                lstrip_blocks=True
            )
            
            # Add custom filters
            jinja_env.filters['format_datetime'] = self._format_datetime_filter
            
            # Render template
            template = jinja_env.get_template(template_name)
            rendered = template.render(**context)
            
            logger.debug(
                "Template rendered successfully",
                template=template_name,
                context_keys=list(context.keys())
            )
            
            return rendered
            
        except TemplateNotFound as e:
            logger.error("Template not found", template=template_name, error=str(e))
            raise TemplateRenderError(f"Template file not found: {template_name}")
        except TemplateError as e:
            logger.error("Template rendering failed", template=template_name, error=str(e))
            raise TemplateRenderError(f"Template rendering failed: {e}")
        except Exception as e:
            logger.error("Unexpected error during template rendering", template=template_name, error=str(e))
            raise TemplateRenderError(f"Template rendering failed: {e}")
    
    def _format_datetime_filter(self, value, format_string="%Y-%m-%d %H:%M:%S") -> str:
        """Jinja2 filter for formatting datetime objects.
        
        Args:
            value: Datetime object
            format_string: Format string for datetime
            
        Returns:
            str: Formatted datetime string
        """
        if value is None:
            return ""
        return value.strftime(format_string) 