import os
from typing import List
from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "Cedrina"
    VERSION: str = "0.1.0"
    APP_ENV: str = "development"
    DEBUG: bool = False

    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_WORKERS: int = 1
    RELOAD: bool = False

    LOG_LEVEL: str = "INFO"
    LOG_JSON: bool = True

    SECRET_KEY: str = Field(..., min_length=32)
    ALLOWED_ORIGINS: List[AnyHttpUrl]
    SUPPORTED_LANGUAGES: List[str] = ["en", "fa", "ar"]
    DEFAULT_LANGUAGE: str = "en"

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_allowed_origins(cls, value: str) -> List[str]:
        if isinstance(value, str):
            return [url.strip() for url in value.strip('[]').split(",") if url.strip()]
        return value

    model_config = SettingsConfigDict(
        env_file=".env" if os.getenv("APP_ENV", "development") == "development" else f".env.{os.getenv('APP_ENV', 'development')}",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

settings = Settings()