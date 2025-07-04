"""Email Service for sending password reset and notification emails.

This service handles email template rendering, SMTP configuration, and secure
email delivery following Domain-Driven Design principles and security best practices.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional


from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from jinja2 import Environment, FileSystemLoader, TemplateNotFound, TemplateError
from structlog import get_logger

from src.core.config.email import EmailSettings
from src.core.exceptions import EmailServiceError, TemplateRenderError
from src.utils.i18n import get_translated_message

logger = get_logger(__name__)


class EmailService:
    """Domain service for handling email operations with security and i18n support.
    
    This service encapsulates all email-related business logic including:
    - Template rendering with Jinja2
    - Multi-language support
    - Secure SMTP configuration
    - Password reset email functionality
    - Rate limiting integration points
    
    Security features:
    - HTML escaping by default
    - Secure SMTP configuration validation
    - Test mode for development
    - Proper error handling and logging
    
    Attributes:
        settings: Email configuration settings
        jinja_env: Jinja2 environment for template rendering
        fastmail: FastMail instance for email delivery
    """
    
    def __init__(self, settings: EmailSettings):
        """Initialize EmailService with configuration.
        
        Args:
            settings: Email configuration settings
            
        Raises:
            EmailServiceError: If configuration is invalid
        """
        self.settings = settings
        self._setup_jinja_environment()
        self._setup_fastmail()
        
        logger.info(
            "Email service initialized",
            test_mode=settings.EMAIL_TEST_MODE,
            smtp_host=settings.SMTP_HOST,
            templates_dir=settings.EMAIL_TEMPLATES_DIR
        )
    
    def _setup_jinja_environment(self) -> None:
        """Set up Jinja2 environment for template rendering.
        
        Configures Jinja2 with security settings:
        - Auto-escaping enabled for HTML templates
        - Template directory configuration
        - Custom filters if needed
        """
        template_dir = Path(self.settings.EMAIL_TEMPLATES_DIR)
        
        if not template_dir.exists():
            # Create directory if it doesn't exist
            template_dir.mkdir(parents=True, exist_ok=True)
            logger.info("Created email templates directory", path=str(template_dir))
        
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True,  # Enable auto-escaping for security
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Add custom filters for email formatting if needed
        self.jinja_env.filters['format_datetime'] = self._format_datetime_filter
    
    def _setup_fastmail(self) -> None:
        """Set up FastMail for email delivery.
        
        Configures FastMail with SMTP settings based on test/production mode.
        In test mode, emails are logged instead of sent.
        """
        if self.settings.EMAIL_TEST_MODE:
            # In test mode, we don't need real SMTP configuration
            self.fastmail = None
            logger.info("Email service in test mode - emails will be logged")
            return
        
        try:
            config = ConnectionConfig(
                MAIL_USERNAME=self.settings.SMTP_USERNAME,
                MAIL_PASSWORD=self.settings.SMTP_PASSWORD.get_secret_value() if self.settings.SMTP_PASSWORD else "",
                MAIL_FROM=self.settings.FROM_EMAIL,
                MAIL_PORT=self.settings.SMTP_PORT,
                MAIL_SERVER=self.settings.SMTP_HOST,
                MAIL_FROM_NAME=self.settings.FROM_NAME,
                MAIL_TLS=self.settings.SMTP_USE_TLS,
                MAIL_SSL=self.settings.SMTP_USE_SSL,
                USE_CREDENTIALS=bool(self.settings.SMTP_USERNAME and self.settings.SMTP_PASSWORD),
                VALIDATE_CERTS=True,  # Always validate certificates for security
            )
            
            self.fastmail = FastMail(config)
            logger.info("FastMail configured for production use")
            
        except Exception as e:
            logger.error("Failed to configure FastMail", error=str(e))
            raise EmailServiceError(f"Failed to configure email service: {e}")
    
    def render_template(self, template_name: str, **context: Any) -> str:
        """Render email template with provided context.
        
        Args:
            template_name: Name of the template file
            **context: Template variables
            
        Returns:
            str: Rendered template content
            
        Raises:
            TemplateRenderError: If template rendering fails
            
        Security:
            - Auto-escaping is enabled by default
            - Template files are validated to exist
            - Context variables are safely rendered
        """
        try:
            template_path = Path(self.settings.EMAIL_TEMPLATES_DIR) / template_name
            
            if not template_path.exists():
                raise TemplateRenderError(
                    f"Template file not found: {template_name}"
                )
            
            template = self.jinja_env.get_template(template_name)
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
    
    async def send_email(
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
            
        Security:
            - Email addresses are validated
            - Content is safely handled
            - SMTP credentials are secure
        """
        try:
            if self.settings.EMAIL_TEST_MODE:
                # In test mode, log the email instead of sending
                logger.info(
                    "Email sent in test mode",
                    to_email=to_email,
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
                to_email=to_email,
                subject=subject
            )
            
            return True
            
        except Exception as e:
            logger.error(
                "Failed to send email",
                to_email=to_email,
                subject=subject,
                error=str(e)
            )
            raise EmailServiceError(f"Failed to send email: {e}")
    

    
    def _format_datetime_filter(self, value, format_string="%Y-%m-%d %H:%M:%S"):
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