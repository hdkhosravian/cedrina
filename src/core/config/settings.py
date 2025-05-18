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
from pydantic import AnyHttpUrl, Field, field_validator, ValidationInfo, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic_core import PydanticCustomError

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Settings(BaseSettings):
    """
    Application settings class that defines and validates all configuration parameters.
    
    This class:
        PROJECT_NAME (str): Name of the project.
        VERSION (str): Application version.
        APP_ENV (Literal): Environment (development, staging, production, test).
        DEBUG (bool): Debug mode flag.
        API_HOST (str): Host for API server.
        API_PORT (int): Port for API server.
        SECRET_KEY (SecretStr): Secret key for cryptographic operations.
        ALLOWED_ORIGINS (List[HttpUrl]): CORS allowed origins.
        POSTGRES_USER (str): PostgreSQL username.
        POSTGRES_PASSWORD (SecretStr): PostgreSQL password.
        POSTGRES_DB (str): PostgreSQL database name.
        POSTGRES_HOST (str): PostgreSQL host.
        POSTGRES_PORT (int): PostgreSQL port.
        POSTGRES_SSL_MODE (str): PostgreSQL SSL mode.
        DATABASE_URL (str): PostgreSQL connection URL.
        REDIS_HOST (str): Redis host.
        REDIS_PORT (int): Redis port.
        REDIS_SSL (bool): Redis SSL flag.
        REDIS_URL (str): Redis connection URL.
        PGCRYPTO_KEY (SecretStr): Key for pgcrypto encryption.
        GOOGLE_CLIENT_ID (str): Google OAuth client ID.
        GOOGLE_CLIENT_SECRET (SecretStr): Google OAuth client secret.
        MICROSOFT_CLIENT_ID (str): Microsoft OAuth client ID.
        MICROSOFT_CLIENT_SECRET (SecretStr): Microsoft OAuth client secret.
        FACEBOOK_CLIENT_ID (str): Facebook OAuth client ID.
        FACEBOOK_CLIENT_SECRET (SecretStr): Facebook OAuth client secret.
        JWT_PRIVATE_KEY (SecretStr): RSA private key for JWT signing.
        JWT_PUBLIC_KEY (str): RSA public key for JWT verification.
        JWT_ISSUER (str): JWT issuer identifier.
        JWT_AUDIENCE (str): JWT audience identifier.
        ACCESS_TOKEN_EXPIRE_MINUTES (int): Access token expiration time.
        REFRESH_TOKEN_EXPIRE_DAYS (int): Refresh token expiration time.
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
    POSTGRES_DB_TEST: str
    POSTGRES_HOST: str
    POSTGRES_PORT: int = Field(ge=1, le=65535)
    POSTGRES_SSL_MODE: str = Field(pattern="^(disable|allow|prefer|require|verify-ca|verify-full)$")
    POSTGRES_POOL_SIZE: int = Field(ge=1)
    POSTGRES_MAX_OVERFLOW: int = Field(ge=0)
    POSTGRES_POOL_TIMEOUT: float = Field(ge=1.0)
    DATABASE_URL: str
    PGCRYPTO_KEY: SecretStr

    # Redis settings
    REDIS_HOST: str
    REDIS_PORT: int = Field(ge=1, le=65535)
    REDIS_PASSWORD: str = Field(default="", exclude=lambda v, info: info.data.get('APP_ENV') in ['staging', 'production'])
    REDIS_SSL: bool = False
    REDIS_URL: str
    
    # Auth settings
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: SecretStr = SecretStr("")
    MICROSOFT_CLIENT_ID: str = ""
    MICROSOFT_CLIENT_SECRET: SecretStr = SecretStr("")
    FACEBOOK_CLIENT_ID: str = ""
    FACEBOOK_CLIENT_SECRET: SecretStr = SecretStr("")
    JWT_PRIVATE_KEY: SecretStr = SecretStr("")  # Generate RSA key pair
    JWT_PUBLIC_KEY: str = ""
    JWT_ISSUER: str = "https://api.cedrina.com"
    JWT_AUDIENCE: str = "cedrina:api:v1"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

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

    model_config = SettingsConfigDict(
        env_file=".env" if os.getenv("APP_ENV", "development") == "development" else f".env.{os.getenv('APP_ENV', 'development')}",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

# Create a singleton instance of the settings
settings = Settings()