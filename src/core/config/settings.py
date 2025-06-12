"""
Main application settings and configuration management.

This module composes all the application settings from the different modules
(app, database, redis, auth) into a single, accessible `Settings` class.

It loads settings from environment variables and .env files, validates them,
and provides a single `settings` object for use throughout the application.
"""

import logging
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
        extra="ignore"
    )

# Create a singleton instance of the settings to be used across the application.
settings = Settings()