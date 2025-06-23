"""
Redis cache settings.
"""
from pydantic import Field, field_validator, ValidationInfo, PydanticUserError, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class RedisSettings(BaseSettings):
    """
    Defines settings for the Redis cache connection.
    """
    REDIS_HOST: str
    REDIS_PORT: int = Field(ge=1, le=65535, default=6379)
    REDIS_PASSWORD: SecretStr = SecretStr("")
    REDIS_SSL: bool = False
    REDIS_URL: str = ""

    # Rate limiting settings
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT: str = "100/minute"  # Default rate limit
    RATE_LIMIT_AUTH: str = "20/minute"      # Stricter limit for auth routes
    RATE_LIMIT_STORAGE_URL: str = ""  # Optional custom storage URL
    RATE_LIMIT_STRATEGY: str = Field(
        default="fixed-window",
        pattern="^(fixed-window|sliding-window|token-bucket)$"
    )
    RATE_LIMIT_BLOCK_DURATION: int = Field(
        default=60,
        ge=1,
        description="Duration in seconds to block after rate limit exceeded"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    @field_validator("REDIS_URL", mode="before")
    @classmethod
    def assemble_redis_url(cls, v: str | None, info: ValidationInfo) -> str:
        """
        Assembles the Redis connection URL if not provided explicitly.
        """
        if v:
            return v
        
        values = info.data
        protocol = "rediss" if values.get("REDIS_SSL") else "redis"
        redis_password = values.get("REDIS_PASSWORD", "")
        password = f":{redis_password}@" if redis_password else ""
        
        return f"{protocol}://{password}{values.get('REDIS_HOST')}:{values.get('REDIS_PORT')}/0"

    @field_validator("REDIS_PASSWORD")
    @classmethod
    def validate_redis_password(cls, value: SecretStr, info: ValidationInfo) -> SecretStr:
        """
        Ensures REDIS_PASSWORD is set for staging/production environments.
        """
        if info.data.get('APP_ENV') in ['staging', 'production'] and not value.get_secret_value():
            raise PydanticUserError(
                'redis_password_required',
                'REDIS_PASSWORD must be set in staging/production environments'
            )
        return value

    @field_validator("RATE_LIMIT_STORAGE_URL", mode="before")
    @classmethod
    def assemble_rate_limit_storage_url(cls, v: str | None, info: ValidationInfo) -> str:
        """
        Assembles the rate limit storage URL if not provided explicitly.
        Uses the main Redis URL by default.
        """
        if v:
            return v
        return cls.assemble_redis_url(None, info) 