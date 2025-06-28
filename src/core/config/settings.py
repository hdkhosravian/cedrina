"""Main application settings and configuration management.

This module composes all the application settings from the different modules
(app, database, redis, auth) into a single, accessible `Settings` class.

It loads settings from environment variables and .env files, validates them,
and provides a single `settings` object for use throughout the application.
"""

import logging

from pydantic_settings import SettingsConfigDict

from .app import AppSettings
from .auth import AuthSettings
from .database import DatabaseSettings
from .redis import RedisSettings

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logging.getLogger("passlib").setLevel(logging.ERROR)


class Settings(AppSettings, DatabaseSettings, RedisSettings, AuthSettings):
    """The main settings class that aggregates all application configurations.

    It inherits from all the specialized settings classes, providing a unified
    interface to all configuration parameters.

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


# Create a singleton instance of the settings to be used across the application.
settings = Settings()
settings.validate_required_fields()
settings.SUPPORTED_LANGUAGES = ["en", "es", "fa", "ar"]

# Password Policy Settings
PASSWORD_MIN_LENGTH = 8
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_LOWERCASE = True
PASSWORD_REQUIRE_DIGIT = True
PASSWORD_REQUIRE_SPECIAL_CHAR = True
BCRYPT_WORK_FACTOR = 12  # Configurable bcrypt rounds, default 12
