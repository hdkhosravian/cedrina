"""
Application settings and configuration management module.

This module defines the application's configuration using Pydantic settings management.
It handles environment variables, validates configuration values, and provides
type-safe access to application settings.

The settings are loaded from environment variables and .env files, with support for
different environments (development, staging, production).
"""

import os
from typing import List
from pydantic import AnyHttpUrl, Field, field_validator, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

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
    ALLOWED_ORIGINS: List[AnyHttpUrl]
    SUPPORTED_LANGUAGES: List[str] = ["en", "fa", "ar"]
    DEFAULT_LANGUAGE: str = "en"

    POSTGRES_USER: str
    POSTGRES_PASSWORD: str = Field(..., min_length=12)
    POSTGRES_DB: str
    POSTGRES_HOST: str
    POSTGRES_PORT: int = Field(ge=1, le=65535, default=5432)
    POSTGRES_SSL_MODE: str = Field(default="prefer", regex="^(disable|allow|prefer|require|verify-ca|verify-full)$")
    POSTGRES_POOL_SIZE: int = Field(ge=1, default=5)
    POSTGRES_MAX_OVERFLOW: int = Field(ge=0, default=10)
    POSTGRES_POOL_TIMEOUT: float = Field(ge=1.0, default=30.0)
    DATABASE_URL: str

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_allowed_origins(cls, value: str) -> List[str]:
        """
        Validates and parses the ALLOWED_ORIGINS setting.
        
        This validator:
        1. Handles both string and list inputs
        2. Parses comma-separated URLs from string
        3. Strips whitespace from URLs
        4. Filters out empty values
        
        Args:
            value (str): The input value to parse
            
        Returns:
            List[str]: List of parsed and validated URLs
        """
        if isinstance(value, str):
            return [url.strip() for url in value.strip('[]').split(",") if url.strip()]
        return value

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, value: str, values: dict) -> str:
        """
        Validates that DATABASE_URL matches other POSTGRES_* settings.
        
        This validator ensures consistency between the DATABASE_URL and individual
        PostgreSQL connection parameters. It constructs the expected URL from
        the individual parameters and compares it with the provided URL.
        
        Args:
            value (str): The DATABASE_URL to validate
            values (dict): Dictionary containing other settings
            
        Returns:
            str: The validated DATABASE_URL
            
        Raises:
            ValidationError: If DATABASE_URL doesn't match POSTGRES_* settings
        """
        expected_url = (
            f"postgresql+psycopg2://{values.get('POSTGRES_USER')}:{values.get('POSTGRES_PASSWORD')}@"
            f"{values.get('POSTGRES_HOST')}:{values.get('POSTGRES_PORT')}/{values.get('POSTGRES_DB')}?sslmode={values.get('POSTGRES_SSL_MODE')}"
        )
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