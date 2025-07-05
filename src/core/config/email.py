"""Email configuration settings for the Cedrina application.

This module defines email-related configuration parameters for sending 
notifications, password reset emails, and other email communications.
Provides secure defaults and validation for production environments.
"""

from typing import Optional

from pydantic import EmailStr, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class EmailSettings(BaseSettings):
    """Email configuration settings with secure defaults and validation.
    
    Security considerations:
    - SMTP credentials are handled as SecretStr to prevent logging
    - TLS is enforced by default for security
    - Rate limiting should be applied at the service layer
    - Email templates are validated to prevent injection attacks
    
    Attributes:
        SMTP_HOST: SMTP server hostname
        SMTP_PORT: SMTP server port (587 for TLS, 465 for SSL)
        SMTP_USERNAME: SMTP authentication username
        SMTP_PASSWORD: SMTP authentication password (SecretStr)
        SMTP_USE_TLS: Enable TLS encryption (recommended)
        SMTP_USE_SSL: Enable SSL encryption (alternative to TLS)
        FROM_EMAIL: Default sender email address
        FROM_NAME: Default sender name
        EMAIL_TEMPLATES_DIR: Directory containing email templates
        PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: Token expiration time
        PASSWORD_RESET_URL_BASE: Base URL for password reset links
        EMAIL_RATE_LIMIT_PER_HOUR: Rate limit for email sending per hour
    """
    
    model_config = SettingsConfigDict(
        env_prefix="EMAIL_",
        case_sensitive=True
    )
    
    # SMTP Configuration
    SMTP_HOST: str = Field(
        default="localhost",
        description="SMTP server hostname"
    )
    SMTP_PORT: int = Field(
        default=587,
        ge=1,
        le=65535,
        description="SMTP server port (587 for TLS, 465 for SSL)"
    )
    SMTP_USERNAME: Optional[str] = Field(
        default=None,
        description="SMTP authentication username"
    )
    SMTP_PASSWORD: Optional[SecretStr] = Field(
        default=None,
        description="SMTP authentication password"
    )
    SMTP_USE_TLS: bool = Field(
        default=True,
        description="Enable TLS encryption (recommended for production)"
    )
    SMTP_USE_SSL: bool = Field(
        default=False,
        description="Enable SSL encryption (alternative to TLS)"
    )
    
    # Email Headers
    FROM_EMAIL: EmailStr = Field(
        default="noreply@example.com",
        description="Default sender email address"
    )
    FROM_NAME: str = Field(
        default="Cedrina",
        description="Default sender name"
    )
    
    # Template Configuration
    EMAIL_TEMPLATES_DIR: str = Field(
        default="src/templates/email",
        description="Directory containing email templates"
    )
    
    # Password Reset Configuration
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = Field(
        default=15,
        ge=1,
        le=1440,  # Maximum 24 hours
        description="Password reset token expiration time in minutes"
    )
    PASSWORD_RESET_URL_BASE: str = Field(
        default="http://localhost:3000/reset-password",
        description="Base URL for password reset links in frontend"
    )
    
    # Rate Limiting
    EMAIL_RATE_LIMIT_PER_HOUR: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Maximum emails per hour per IP/user for security"
    )
    
    # Test Configuration
    EMAIL_TEST_MODE: bool = Field(
        default=False,
        description="Enable test mode (emails logged instead of sent)"
    )
    
    def validate_smtp_config(self) -> None:
        """Validate SMTP configuration for production use.
        
        Raises:
            ValueError: If SMTP configuration is invalid or insecure
        """
        # Skip validation in non-production or test environments
        if self.EMAIL_TEST_MODE or getattr(self, "APP_ENV", "development") not in {"production", "staging"}:
            return

        if not self.SMTP_USERNAME or not self.SMTP_PASSWORD:
            raise ValueError(
                "SMTP_USERNAME and SMTP_PASSWORD are required in production"
            )
        
        if not (self.SMTP_USE_TLS or self.SMTP_USE_SSL):
            raise ValueError(
                "Either SMTP_USE_TLS or SMTP_USE_SSL must be enabled for security"
            )
        
        if self.SMTP_USE_TLS and self.SMTP_USE_SSL:
            raise ValueError(
                "Cannot enable both SMTP_USE_TLS and SMTP_USE_SSL simultaneously"
            ) 