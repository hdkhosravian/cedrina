"""
Application-specific settings.
"""
from typing import List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class AppSettings(BaseSettings):
    """
    Defines application-wide settings like project name, debug mode, and CORS origins.

    Security Note:
        - Ensure ALLOWED_ORIGINS is explicitly set to trusted domains in production
          to prevent unauthorized cross-origin requests
          (OWASP A05:2021 - Security Misconfiguration).
        - SECRET_KEY must be a cryptographically secure random string
          (minimum 32 characters) to protect against session hijacking or
          token forgery.
    Performance Note:
        - API_WORKERS should be tuned based on server capacity and traffic load
          to optimize throughput without overloading resources.
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
    ALLOWED_ORIGINS: Union[str, List[str]] = Field(default="http://0.0.0.0:8000")
    DEFAULT_LANGUAGE: str = "en"

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """
        Splits a comma-separated string of origins into a list.

        Args:
            v: Input value as a string or list of origins.

        Returns:
            List of stripped origin strings.
        """
        if isinstance(v, str):
            return [i.strip() for i in v.split(",")]
        return v