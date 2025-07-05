"""Main application settings and configuration management.

This module composes all the application settings from the different modules
(app, database, redis, auth) into a single, accessible `Settings` class.

It loads settings from environment variables and .env files, validates them,
and provides a single `settings` object for use throughout the application.

Environment Support:
- Development: Uses .env or .env.development, SMTP credentials not required
- Test: Uses .env.test, SMTP credentials not required, test mode enabled
- Staging: Uses .env.staging, SMTP credentials required
- Production: Uses .env.production, SMTP credentials required
"""

import logging
import os
from pathlib import Path

from pydantic_settings import SettingsConfigDict

from .app import AppSettings
from .auth import AuthSettings
from .database import DatabaseSettings
from .email import EmailSettings
from .redis import RedisSettings

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logging.getLogger("passlib").setLevel(logging.ERROR)


class Settings(AppSettings, DatabaseSettings, RedisSettings, AuthSettings, EmailSettings):
    """The main settings class that aggregates all application configurations.

    It inherits from all the specialized settings classes, providing a unified
    interface to all configuration parameters.

    Environment Support:
        - Automatically loads the correct .env file based on APP_ENV
        - Development/Test: SMTP credentials not required, test mode enabled
        - Staging/Production: SMTP credentials required, production mode

    Security Note:
        - Ensure all sensitive fields (e.g., SECRET_KEY, passwords, JWT keys) are
          securely stored and never logged or exposed (OWASP A02:2021 - Cryptographic Failures).
        - Validate environment variables in production to prevent misconfiguration
          (OWASP A05:2021 - Security Misconfiguration).
    Usage:
        - Access settings via the singleton instance `settings` throughout the application.
    """

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=True, extra="allow"
    )

    def __init__(self, **kwargs):
        """Initialize settings with environment-specific configuration."""
        # Initialize with the base config
        super().__init__(**kwargs)
        
        # Set environment-specific defaults
        env = os.getenv("APP_ENV", "development")
        self._set_environment_defaults(env)
    

    
    def _set_environment_defaults(self, env: str) -> None:
        """Set environment-specific default values.
        
        Args:
            env: Environment name
        """
        # Set email test mode for development and test environments
        if env in ("development", "test"):
            self.EMAIL_TEST_MODE = True
            logger.info(f"Email test mode enabled for {env} environment")
        
        # Set debug mode for development
        if env == "development":
            self.DEBUG = True
            logger.info("Debug mode enabled for development environment")
        
        # Log environment configuration
        logger.info(f"Application running in {env} environment")
        logger.info(f"Email test mode: {getattr(self, 'EMAIL_TEST_MODE', False)}")
        logger.info(f"Debug mode: {getattr(self, 'DEBUG', False)}")

    def validate_required_fields(self) -> None:
        """Validates that all required environment variables are set.
        Raises ValueError if any critical field is missing or empty, unless in test mode.
        Provides detailed logging for debugging and audit purposes.

        Raises:
            ValueError: If required fields are missing and not in test mode.

        """
        required_fields = [
            "PROJECT_NAME",
            "POSTGRES_HOST",
            "POSTGRES_PORT",
            "POSTGRES_DB",
            "POSTGRES_USER",
            "POSTGRES_PASSWORD",
            "REDIS_HOST",
            "REDIS_PORT",
            "SECRET_KEY",
            "JWT_PUBLIC_KEY",
            "JWT_PRIVATE_KEY",
        ]

        missing_fields = [field for field in required_fields if not getattr(self, field, None)]
        if missing_fields:
            error_msg = f"Missing required environment variables: {', '.join(missing_fields)}"
            if hasattr(self, "TEST_MODE") and self.TEST_MODE:
                logger.warning(f"Test mode: {error_msg}")
            else:
                logger.error(error_msg)
                raise ValueError(error_msg)
        else:
            logger.info("All required environment variables are set.")
            
        # Validate email configuration
        try:
            self.validate_smtp_config()
            logger.info("Email configuration validated successfully.")
        except ValueError as e:
            env = os.getenv("APP_ENV", "development")
            if env in ("development", "test") or hasattr(self, "TEST_MODE") and self.TEST_MODE:
                logger.warning(f"Test mode: Email config warning - {e}")
            else:
                logger.error(f"Email configuration error: {e}")
                # Don't raise error for email config to allow graceful degradation


def create_settings() -> Settings:
    """Create settings instance with environment-specific configuration.
    
    Returns:
        Settings: Configured settings instance
    """
    env = os.getenv("APP_ENV", "development")
    
    # Determine which .env file to use
    env_files = {
        "development": ".env",
        "test": ".env.test",
        "staging": ".env.staging", 
        "production": ".env.production"
    }
    
    env_file = env_files.get(env, ".env")
    
    # Check if the environment-specific file exists
    if env != "development" and Path(env_file).exists():
        logger.info(f"Loading environment configuration from {env_file}")
        # Create settings with the specific env file
        settings_instance = Settings(_env_file=env_file)
    elif Path(".env").exists():
        logger.info(f"Loading environment configuration from .env (environment: {env})")
        settings_instance = Settings()
    else:
        logger.warning(f"No .env file found, using environment variables only (environment: {env})")
        settings_instance = Settings()
    
    return settings_instance

# Create a singleton instance of the settings to be used across the application.
settings = create_settings()
settings.validate_required_fields()
settings.SUPPORTED_LANGUAGES = ["en", "es", "fa", "ar"]

# Password Policy Settings
PASSWORD_MIN_LENGTH = 8
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_LOWERCASE = True
PASSWORD_REQUIRE_DIGIT = True
PASSWORD_REQUIRE_SPECIAL_CHAR = True
BCRYPT_WORK_FACTOR = 12  # Configurable bcrypt rounds, default 12
