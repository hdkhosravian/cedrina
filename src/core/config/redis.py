"""
Redis cache settings.
"""
from pydantic import Field, field_validator, ValidationInfo, PydanticCustomError, SecretStr
from pydantic_settings import BaseSettings


class RedisSettings(BaseSettings):
    """
    Defines settings for the Redis cache connection.
    """
    REDIS_HOST: str
    REDIS_PORT: int = Field(ge=1, le=65535, default=6379)
    REDIS_PASSWORD: SecretStr = SecretStr("")
    REDIS_SSL: bool = False
    REDIS_URL: str = ""

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
            raise PydanticCustomError(
                'redis_password_required',
                'REDIS_PASSWORD must be set in staging/production environments'
            )
        return value 