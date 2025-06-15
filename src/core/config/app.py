"""
Application-specific settings.
"""
from typing import List
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings
import os


class AppSettings(BaseSettings):
    """
    Defines application-wide settings like project name, debug mode, and CORS origins.
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
    ALLOWED_ORIGINS: str | List[str] = Field(default="http://0.0.0.0:8000")
    DEFAULT_LANGUAGE: str = "en"

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: str | List[str]) -> List[str]:
        """
        Splits a comma-separated string of origins into a list.
        """
        if isinstance(v, str):
            return [i.strip() for i in v.split(",")]
        return v 