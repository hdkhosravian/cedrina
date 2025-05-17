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
from pydantic import AnyHttpUrl, Field, field_validator, ValidationInfo
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic_core import PydanticCustomError

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
    REDIS_PASSWORD: str = Field(default="", exclude=lambda v, info: info.data.get('APP_ENV') in ['staging', 'production'])
    REDIS_SSL: bool = False
    REDIS_URL: str

    @field_validator("ALLOWED_ORIGINS", mode="after")
    @classmethod
    def parse_allowed_origins(cls, value: str) -> List[AnyHttpUrl]:
        """
        Validates and parses the ALLOWED_ORIGINS setting.
        """
        urls = [url.strip() for url in value.split(",") if url.strip()]
        return [AnyHttpUrl(url) for url in urls]

    @field_validator("REDIS_PASSWORD")
    @classmethod
    def validate_redis_password(cls, value: str, info: ValidationInfo) -> str:
        """
        Ensures REDIS_PASSWORD is set for staging/production.
        """
        if info.data.get('APP_ENV') in ['staging', 'production'] and not value:
            raise PydanticCustomError(
                'redis_password_required',
                'REDIS_PASSWORD must be set in staging/production environments'
            )
        return value

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, value: str, info: ValidationInfo) -> str:
        """
        Validates that DATABASE_URL matches other POSTGRES_* settings.
        """
        data = info.data
        
        # In Docker, use port 5432 internally; locally, use POSTGRES_PORT
        effective_port = 5432 if data.get('POSTGRES_HOST') == 'postgres' else data['POSTGRES_PORT']
        
        expected_url = (
            f"postgresql+psycopg2://{data['POSTGRES_USER']}:{data['POSTGRES_PASSWORD']}@"
            f"{data['POSTGRES_HOST']}:{effective_port}/{data['POSTGRES_DB']}?sslmode={data['POSTGRES_SSL_MODE']}"
        )
        logger.debug(f"Expected DATABASE_URL: {expected_url}")
        logger.debug(f"Provided DATABASE_URL: {value}")
        
        if value != expected_url:
            raise PydanticCustomError(
                'database_url_mismatch',
                f"DATABASE_URL must match POSTGRES_* settings. Expected: {expected_url}",
                {'expected_url': expected_url, 'provided_url': value}
            )
        return value

    model_config = SettingsConfigDict(
        env_file=".env" if os.getenv("APP_ENV", "development") == "development" else f".env.{os.getenv('APP_ENV', 'development')}",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

# Create a singleton instance of the settings
settings = Settings()