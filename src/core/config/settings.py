"""
Application settings and configuration management module.

This module defines the application's configuration using Pydantic settings management.
It handles environment variables, validates configuration values, and provides
type-safe access to application settings.

The settings are loaded from environment variables and .env files, with support for
different environments (development, staging, production).
"""

import os
import logging
from typing import List
from pydantic import AnyHttpUrl, Field, field_validator, ValidationError, ValidationInfo
from pydantic_settings import BaseSettings, SettingsConfigDict

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Settings(BaseSettings):
    """
    Application settings class that defines and validates all configuration parameters.
    
    This class:
    - Defines default values for all settings
    - Validates configuration values
    - Handles environment-specific settings
    - Manages database connection parameters
    - Controls application behavior
    
    Attributes:
        PROJECT_NAME (str): Name of the project
        VERSION (str): Application version
        APP_ENV (str): Current environment (development/staging/production)
        DEBUG (bool): Debug mode flag
        API_HOST (str): Host address for the API
        API_PORT (int): Port number for the API
        API_WORKERS (int): Number of worker processes
        RELOAD (bool): Auto-reload flag for development
        LOG_LEVEL (str): Logging level
        LOG_JSON (bool): JSON logging format flag
        SECRET_KEY (str): Application secret key
        ALLOWED_ORIGINS (List[AnyHttpUrl]): List of allowed CORS origins
        SUPPORTED_LANGUAGES (List[str]): List of supported language codes
        DEFAULT_LANGUAGE (str): Default language code
        POSTGRES_*: Database connection parameters
        DATABASE_URL (str): Complete database connection URL
        REDIS_*: Redis connection parameters
        REDIS_URL (str): Complete Redis connection URL
        ENABLE_LOCAL_*: Flags for local service usage
    """
    
    PROJECT_NAME: str = "cedrina"
    VERSION: str = "0.1.0"
    APP_ENV: str = "development"
    DEBUG: bool = False

    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_WORKERS: int = Field(ge=1, default=1)
    RELOAD: bool = False

    LOG_LEVEL: str = "INFO"
    LOG_JSON: bool = True

    SECRET_KEY: str = Field(..., min_length=32)
    ALLOWED_ORIGINS: str = Field(default="http://0.0.0.0:8000")
    SUPPORTED_LANGUAGES: List[str] = ["en", "fa", "ar"]
    DEFAULT_LANGUAGE: str = "en"

    # Database settings - all required from environment
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    POSTGRES_HOST: str
    POSTGRES_PORT: int = Field(ge=1, le=65535)
    POSTGRES_SSL_MODE: str = Field(pattern="^(disable|allow|prefer|require|verify-ca|verify-full)$")
    POSTGRES_POOL_SIZE: int = Field(ge=1)
    POSTGRES_MAX_OVERFLOW: int = Field(ge=0)
    POSTGRES_POOL_TIMEOUT: float = Field(ge=1.0)
    DATABASE_URL: str

    # Redis settings
    REDIS_HOST: str
    REDIS_PORT: int = Field(ge=1, le=65535)
    REDIS_PASSWORD: str
    REDIS_SSL: bool = False
    REDIS_URL: str

    # Local service flags
    ENABLE_LOCAL_POSTGRES: bool = False
    ENABLE_LOCAL_REDIS: bool = False

    @field_validator("ALLOWED_ORIGINS", mode="after")
    @classmethod
    def parse_allowed_origins(cls, value: str) -> List[AnyHttpUrl]:
        """
        Validates and parses the ALLOWED_ORIGINS setting.
        
        This validator:
        1. Splits the input string by comma
        2. Strips whitespace from each URL
        3. Validates each URL as an AnyHttpUrl
        
        Args:
            value (str): Comma-separated list of URLs
            
        Returns:
            List[AnyHttpUrl]: List of validated URLs
        """
        urls = [url.strip() for url in value.split(",") if url.strip()]
        return [AnyHttpUrl(url) for url in urls]

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, value: str, info: ValidationInfo) -> str:
        """
        Validates that DATABASE_URL matches other POSTGRES_* settings.
        
        This validator ensures consistency between the DATABASE_URL and individual
        PostgreSQL connection parameters. It constructs the expected URL from
        the individual parameters and compares it with the provided URL.
        
        Args:
            value (str): The DATABASE_URL to validate
            info (ValidationInfo): Validation info containing other field values
            
        Returns:
            str: The validated DATABASE_URL
            
        Raises:
            ValidationError: If DATABASE_URL doesn't match POSTGRES_* settings
        """
        data = info.data
        
        expected_url = (
            f"postgresql+psycopg2://{data['POSTGRES_USER']}:{data['POSTGRES_PASSWORD']}@"
            f"{data['POSTGRES_HOST']}:{data['POSTGRES_PORT']}/{data['POSTGRES_DB']}?sslmode={data['POSTGRES_SSL_MODE']}"
        )
        logger.debug(f"Expected DATABASE_URL: {expected_url}")
        logger.debug(f"Provided DATABASE_URL: {value}")
        
        if value != expected_url:
            raise ValidationError(f"DATABASE_URL must match POSTGRES_* settings. Expected: {expected_url}")
        return value

    model_config = SettingsConfigDict(
        env_file=".env" if os.getenv("APP_ENV", "development") == "development" else f".env.{os.getenv('APP_ENV', 'development')}",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

# Create a singleton instance of the settings
settings = Settings()