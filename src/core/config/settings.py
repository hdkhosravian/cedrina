"""
Main application settings and configuration management.

This module composes all the application settings from the different modules
(app, database, redis, auth) into a single, accessible `Settings` class.

It loads settings from environment variables and .env files, validates them,
and provides a single `settings` object for use throughout the application.
"""

import logging
import os
from pydantic_settings import BaseSettings, SettingsConfigDict

from .app import AppSettings
from .auth import AuthSettings
from .database import DatabaseSettings
from .redis import RedisSettings

# Set up logging
logging.basicConfig(level=logging.INFO)
logging.getLogger("passlib").setLevel(logging.ERROR)


class Settings(AppSettings, DatabaseSettings, RedisSettings, AuthSettings):
    """
    The main settings class that aggregates all application configurations.
    
    It inherits from all the specialized settings classes, providing a unified
    interface to all configuration parameters.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="allow"
    )
    
    def validate_required_fields(self):
        """
        Validate that all required environment variables are set.
        Raises ValueError if any critical field is missing or empty, unless in test mode.
        """
        required_fields = [
            'PROJECT_NAME',
            'POSTGRES_HOST',
            'POSTGRES_PORT',
            'POSTGRES_DB',
            'POSTGRES_USER',
            'POSTGRES_PASSWORD',
            'REDIS_HOST',
            'REDIS_PORT',
            'SECRET_KEY',
            'JWT_PUBLIC_KEY',
            'JWT_PRIVATE_KEY',
        ]
        
        missing_fields = [field for field in required_fields if not getattr(self, field)]
        if missing_fields:
            error_msg = f"Missing required environment variables: {', '.join(missing_fields)}"
            if self.TEST_MODE:
                logging.warning(f"Test mode: {error_msg}")
            else:
                raise ValueError(error_msg)
        else:
            logging.info("All required environment variables are set.")

# Create a singleton instance of the settings to be used across the application.
settings = Settings()
settings.validate_required_fields()
settings.SUPPORTED_LANGUAGES = ["en", "fa", "ar"]