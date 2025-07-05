"""Unified email service implementation for production use.

This service implements the IEmailService interface and provides a comprehensive,
production-ready email solution that handles all email operations including
password reset, email confirmation, welcome emails, and notifications.

Key Features:
- Secure SMTP configuration with TLS/SSL support
- Multi-language template rendering with Jinja2
- Rate limiting integration for abuse prevention
- Comprehensive error handling and logging
- Test mode for development and testing
- Production-ready with proper security measures

Security Features:
- HTML escaping by default to prevent XSS
- Secure SMTP configuration validation
- Rate limiting to prevent email abuse
- Audit logging for all email operations
- Proper error handling without information disclosure
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timezone

import structlog
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from jinja2 import Environment, FileSystemLoader, TemplateNotFound, TemplateError

from src.core.config.settings import settings
from src.core.exceptions import EmailServiceError, TemplateRenderError
from src.domain.entities.user import User
from src.domain.interfaces.email import IEmailService
from src.domain.value_objects.reset_token import ResetToken
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class UnifiedEmailService(IEmailService):
    """Production-grade unified email service implementation.
    
    This service provides a comprehensive email solution that handles all
    email operations with proper security, rate limiting, and error handling.
    It follows clean architecture principles by implementing the domain interface
    while handling infrastructure concerns.
    
    Attributes:
        settings: Email configuration settings
        jinja_env: Jinja2 environment for template rendering
        fastmail: FastMail instance for email delivery
        rate_limiter: Rate limiting service for abuse prevention
        supported_languages: List of supported languages
    """
    
    def __init__(self):
        """Initialize the unified email service.
        
        Sets up SMTP configuration, template rendering, and rate limiting
        based on the application settings and environment.
        
        Raises:
            EmailServiceError: If configuration is invalid
        """
        self._setup_configuration()
        self._setup_template_environment()
        self._setup_smtp_client()
        self._setup_rate_limiting()
        
        logger.info(
            "UnifiedEmailService initialized",
            test_mode=self.is_test_mode(),
            smtp_configured=bool(settings.EMAIL_SMTP_USERNAME),
            templates_dir=settings.EMAIL_TEMPLATES_DIR,
            supported_languages=self.get_supported_languages()
        )
    
    def _setup_configuration(self) -> None:
        """Set up email configuration and validation."""
        # Validate email configuration
        try:
            settings.validate_smtp_config()
        except ValueError as e:
            logger.warning(f"Email configuration validation warning: {e}")
            # Don't fail initialization, but log the warning
    
    def _setup_template_environment(self) -> None:
        """Set up Jinja2 environment for secure template rendering.
        
        Configures Jinja2 with security settings:
        - Auto-escaping enabled for HTML templates
        - Template directory configuration
        - Custom filters for email formatting
        """
        template_dir = Path(settings.EMAIL_TEMPLATES_DIR)
        
        # Create template directory if it doesn't exist
        if not template_dir.exists():
            template_dir.mkdir(parents=True, exist_ok=True)
            logger.info("Created email templates directory", path=str(template_dir))
        
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True,  # Enable auto-escaping for security
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Add custom filters for email formatting
        self.jinja_env.filters['format_datetime'] = self._format_datetime_filter
        self.jinja_env.filters['mask_email'] = self._mask_email_filter
    
    def _setup_smtp_client(self) -> None:
        """Set up FastMail for secure email delivery.
        
        Configures FastMail with SMTP settings based on test/production mode.
        In test mode, emails are logged instead of sent.
        """
        if self.is_test_mode():
            self.fastmail = None
            logger.info("Email service in test mode - emails will be logged")
            return
        
        try:
            config = ConnectionConfig(
                MAIL_USERNAME=settings.EMAIL_SMTP_USERNAME,
                MAIL_PASSWORD=settings.EMAIL_SMTP_PASSWORD.get_secret_value() if settings.EMAIL_SMTP_PASSWORD else "",
                MAIL_FROM=settings.EMAIL_FROM_EMAIL,
                MAIL_PORT=settings.EMAIL_SMTP_PORT,
                MAIL_SERVER=settings.EMAIL_SMTP_HOST,
                MAIL_FROM_NAME=settings.EMAIL_FROM_NAME,
                MAIL_TLS=settings.EMAIL_SMTP_USE_TLS,
                MAIL_SSL=settings.EMAIL_SMTP_USE_SSL,
                USE_CREDENTIALS=bool(settings.EMAIL_SMTP_USERNAME and settings.EMAIL_SMTP_PASSWORD),
                VALIDATE_CERTS=True,  # Always validate certificates for security
            )
            
            self.fastmail = FastMail(config)
            logger.info("FastMail configured for production use")
            
        except Exception as e:
            logger.error("Failed to configure FastMail", error=str(e))
            raise EmailServiceError(f"Failed to configure email service: {e}")
    
    def _setup_rate_limiting(self) -> None:
        """Set up rate limiting for email abuse prevention."""
        # Import here to avoid circular dependencies
        from src.core.rate_limiting.email_rate_limiter import EmailRateLimiter
        self.rate_limiter = EmailRateLimiter()
    
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
        try:
            # Check rate limiting
            if await self.is_rate_limited(user.id, "password_reset"):
                logger.warning("Rate limit exceeded for password reset email", user_id=user.id)
                raise EmailServiceError("Rate limit exceeded for password reset emails")
            
            # Generate reset URL
            reset_url = self._generate_reset_url(token.value)
            
            # Prepare email context
            context = {
                'user_name': user.username or user.email.split('@')[0],
                'reset_url': reset_url,
                'token_expires_minutes': settings.EMAIL_PASSWORD_RESET_TOKEN_EXPIRE_MINUTES,
                'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@example.com'),
                'app_name': getattr(settings, 'PROJECT_NAME', 'Cedrina'),
            }
            
            # Send email
            subject = get_translated_message("password_reset_email_subject", language)
            success = await self._send_email_with_template(
                user=user,
                subject=subject,
                template_name="password_reset.html",
                context=context,
                language=language
            )
            
            if success:
                # Record successful attempt for rate limiting
                await self.record_email_attempt(user.id, "password_reset")
                logger.info(
                    "Password reset email sent successfully",
                    user_id=user.id,
                    email_masked=self._mask_email(user.email),
                    language=language,
                    expires_at=token.expires_at.isoformat()
                )
            
            return success
            
        except Exception as e:
            logger.error(
                "Failed to send password reset email",
                user_id=user.id,
                error=str(e),
                language=language
            )
            raise EmailServiceError(f"Failed to send password reset email: {e}")
    
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
        try:
            # Check rate limiting
            if await self.is_rate_limited(user.id, "email_confirmation"):
                logger.warning("Rate limit exceeded for email confirmation", user_id=user.id)
                raise EmailServiceError("Rate limit exceeded for confirmation emails")
            
            # Generate confirmation URL
            confirmation_url = self._generate_confirmation_url(confirmation_token)
            
            # Prepare email context
            context = {
                'user_name': user.username or user.email.split('@')[0],
                'confirmation_url': confirmation_url,
                'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@example.com'),
                'app_name': getattr(settings, 'PROJECT_NAME', 'Cedrina'),
            }
            
            # Send email
            subject = get_translated_message("email_confirmation_subject", language)
            success = await self._send_email_with_template(
                user=user,
                subject=subject,
                template_name="email_confirmation.html",
                context=context,
                language=language
            )
            
            if success:
                # Record successful attempt for rate limiting
                await self.record_email_attempt(user.id, "email_confirmation")
                logger.info(
                    "Email confirmation sent successfully",
                    user_id=user.id,
                    email_masked=self._mask_email(user.email),
                    language=language
                )
            
            return success
            
        except Exception as e:
            logger.error(
                "Failed to send email confirmation",
                user_id=user.id,
                error=str(e),
                language=language
            )
            raise EmailServiceError(f"Failed to send email confirmation: {e}")
    
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
        try:
            # Prepare email context
            context = {
                'user_name': user.username or user.email.split('@')[0],
                'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@example.com'),
                'app_name': getattr(settings, 'PROJECT_NAME', 'Cedrina'),
            }
            
            # Send email
            subject = get_translated_message("welcome_email_subject", language)
            success = await self._send_email_with_template(
                user=user,
                subject=subject,
                template_name="welcome.html",
                context=context,
                language=language
            )
            
            if success:
                logger.info(
                    "Welcome email sent successfully",
                    user_id=user.id,
                    email_masked=self._mask_email(user.email),
                    language=language
                )
            
            return success
            
        except Exception as e:
            logger.error(
                "Failed to send welcome email",
                user_id=user.id,
                error=str(e),
                language=language
            )
            raise EmailServiceError(f"Failed to send welcome email: {e}")
    
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
        try:
            # Add common context variables
            context.update({
                'user_name': user.username or user.email.split('@')[0],
                'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@example.com'),
                'app_name': getattr(settings, 'PROJECT_NAME', 'Cedrina'),
            })
            
            success = await self._send_email_with_template(
                user=user,
                subject=subject,
                template_name=template_name,
                context=context,
                language=language
            )
            
            if success:
                logger.info(
                    "Notification email sent successfully",
                    user_id=user.id,
                    email_masked=self._mask_email(user.email),
                    template=template_name,
                    language=language
                )
            
            return success
            
        except Exception as e:
            logger.error(
                "Failed to send notification email",
                user_id=user.id,
                template=template_name,
                error=str(e),
                language=language
            )
            raise EmailServiceError(f"Failed to send notification email: {e}")
    
    async def is_rate_limited(self, user_id: int, email_type: str) -> bool:
        """Check if user is rate limited for specific email type.
        
        Args:
            user_id: User ID to check rate limit for
            email_type: Type of email (e.g., 'password_reset', 'confirmation')
            
        Returns:
            bool: True if user is rate limited
        """
        return await self.rate_limiter.is_rate_limited(user_id, email_type)
    
    async def record_email_attempt(self, user_id: int, email_type: str) -> None:
        """Record email sending attempt for rate limiting.
        
        Args:
            user_id: User ID to record attempt for
            email_type: Type of email sent
        """
        await self.rate_limiter.record_attempt(user_id, email_type)
    
    def get_supported_languages(self) -> list[str]:
        """Get list of supported languages for email templates.
        
        Returns:
            list[str]: List of supported language codes
        """
        return getattr(settings, 'SUPPORTED_LANGUAGES', ['en', 'es', 'fa', 'ar'])
    
    def is_test_mode(self) -> bool:
        """Check if email service is in test mode.
        
        Returns:
            bool: True if in test mode (emails logged instead of sent)
        """
        return getattr(settings, 'EMAIL_TEST_MODE', True)
    
    async def _send_email_with_template(
        self,
        user: User,
        subject: str,
        template_name: str,
        context: Dict[str, Any],
        language: str = "en"
    ) -> bool:
        """Send email using template with proper error handling.
        
        Args:
            user: User entity to send email to
            subject: Email subject
            template_name: Template file name
            context: Template context variables
            language: Language for localization
            
        Returns:
            bool: True if email sent successfully
            
        Raises:
            EmailServiceError: If email sending fails
        """
        try:
            # Render template
            html_content = self._render_template(template_name, **context)
            
            # Generate text version (strip HTML tags)
            text_content = self._html_to_text(html_content)
            
            # Send email
            return await self._send_email(
                to_email=user.email,
                subject=subject,
                html_content=html_content,
                text_content=text_content
            )
            
        except TemplateRenderError as e:
            logger.error("Template rendering failed", template=template_name, error=str(e))
            raise EmailServiceError(f"Template rendering failed: {e}")
        except Exception as e:
            logger.error("Email sending failed", template=template_name, error=str(e))
            raise EmailServiceError(f"Email sending failed: {e}")
    
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
            template_path = Path(settings.EMAIL_TEMPLATES_DIR) / template_name
            
            if not template_path.exists():
                # Try with language suffix
                lang_template_name = f"{template_name.replace('.html', '')}_{context.get('language', 'en')}.html"
                template_path = Path(settings.EMAIL_TEMPLATES_DIR) / lang_template_name
                
                if not template_path.exists():
                    raise TemplateRenderError(f"Template file not found: {template_name}")
            
            template = self.jinja_env.get_template(template_path.name)
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
    
    async def _send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None
    ) -> bool:
        """Send email with HTML and optional text content.
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML email content
            text_content: Optional plain text content
            
        Returns:
            bool: True if email sent successfully
            
        Raises:
            EmailServiceError: If email sending fails
        """
        try:
            if self.is_test_mode():
                # In test mode, log the email instead of sending
                logger.info(
                    "Email sent in test mode",
                    to_email=self._mask_email(to_email),
                    subject=subject,
                    html_length=len(html_content),
                    text_length=len(text_content) if text_content else 0
                )
                return True
            
            if not self.fastmail:
                raise EmailServiceError("FastMail not configured for production mode")
            
            message = MessageSchema(
                subject=subject,
                recipients=[to_email],
                body=html_content,
                subtype="html"
            )
            
            # Add text alternative if provided
            if text_content:
                message.alternative_body = text_content
            
            await self.fastmail.send_message(message)
            
            logger.info(
                "Email sent successfully",
                to_email=self._mask_email(to_email),
                subject=subject
            )
            
            return True
            
        except Exception as e:
            logger.error(
                "Failed to send email",
                to_email=self._mask_email(to_email),
                subject=subject,
                error=str(e)
            )
            raise EmailServiceError(f"Failed to send email: {e}")
    
    def _generate_reset_url(self, token: str) -> str:
        """Generate password reset URL with token.
        
        Args:
            token: Reset token to include in URL
            
        Returns:
            str: Complete reset URL
        """
        base_url = getattr(settings, 'PASSWORD_RESET_URL_BASE', 'http://localhost:3000')
        return f"{base_url}/reset-password?token={token}"
    
    def _generate_confirmation_url(self, token: str) -> str:
        """Generate email confirmation URL with token.
        
        Args:
            token: Confirmation token to include in URL
            
        Returns:
            str: Complete confirmation URL
        """
        base_url = getattr(settings, 'PASSWORD_RESET_URL_BASE', 'http://localhost:3000')
        return f"{base_url}/confirm-email?token={token}"
    
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
    
    def _mask_email_filter(self, email: str) -> str:
        """Jinja2 filter for masking email addresses in templates.
        
        Args:
            email: Email address to mask
            
        Returns:
            str: Masked email address
        """
        return self._mask_email(email)
    
    def _mask_email(self, email: str) -> str:
        """Mask email address for logging security.
        
        Args:
            email: Email address to mask
            
        Returns:
            str: Masked email address
        """
        if not email or '@' not in email:
            return "unknown"
        
        username, domain = email.split('@', 1)
        if len(username) <= 3:
            masked_username = username
        else:
            masked_username = username[:3] + "***"
        
        return f"{masked_username}@{domain}"
    
    def _html_to_text(self, html_content: str) -> str:
        """Convert HTML content to plain text.
        
        Args:
            html_content: HTML content to convert
            
        Returns:
            str: Plain text version
        """
        # Simple HTML to text conversion
        # In production, consider using a proper HTML parser
        import re
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', html_content)
        
        # Decode HTML entities
        import html
        text = html.unescape(text)
        
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text 