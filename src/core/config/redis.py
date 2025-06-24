"""
Redis cache settings.
"""
from pydantic import Field, field_validator, ValidationInfo, PydanticUserError, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
import logging

logger = logging.getLogger(__name__)


class RedisSettings(BaseSettings):
    """
    Defines settings for the Redis cache connection.

    Security Note:
        - REDIS_PASSWORD must be set in production to prevent unauthorized access
          (OWASP A05:2021 - Security Misconfiguration).
        - RATE_LIMIT_STORAGE_URL should use secure protocols (rediss://) in production
          with proper TLS configuration.
    Performance Note:
        - Rate limiting strategy impacts performance; 'fixed-window' is lightweight but
          less precise than 'sliding-window' or 'token-bucket' for burst traffic.
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
        Masks password in logs for security.

        Args:
            v: Explicitly provided URL or None.
            info: Validation context with other field values.

        Returns:
            Assembled or provided Redis URL.
        """
        if v:
            return v
        
        values = info.data
        protocol = "rediss" if values.get("REDIS_SSL") else "redis"
        redis_password = values.get("REDIS_PASSWORD", "")
        password = f":{redis_password}@" if redis_password else ""
        
        url = f"{protocol}://{password}{values.get('REDIS_HOST')}:{values.get('REDIS_PORT')}/0"
        logger.debug("Assembled REDIS_URL (password masked for security).")
        return url

    @field_validator("REDIS_PASSWORD")
    @classmethod
    def validate_redis_password(cls, value: SecretStr, info: ValidationInfo) -> SecretStr:
        """
        Ensures REDIS_PASSWORD is set for staging/production environments.

        Args:
            value: The password value to validate.
            info: Validation context with other field values.

        Returns:
            Validated password value.

        Raises:
            PydanticUserError: If password is not set in staging/production.
        """
        app_env = info.data.get('APP_ENV', 'development')
        if app_env in ['staging', 'production'] and not value.get_secret_value():
            logger.error(f"REDIS_PASSWORD must be set in {app_env} environment.")
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

        Args:
            v: Explicitly provided storage URL or None.
            info: Validation context with other field values.

        Returns:
            Assembled or provided storage URL.
        """
        if v:
            return v
        url = cls.assemble_redis_url(None, info)
        logger.debug("Assembled RATE_LIMIT_STORAGE_URL using REDIS_URL.")
        return url

    @field_validator("RATE_LIMIT_DEFAULT", "RATE_LIMIT_AUTH")
    @classmethod
    def validate_rate_limit_format(cls, value: str) -> str:
        """
        Validates the format of rate limit strings (e.g., '100/minute').

        Args:
            value: Rate limit string to validate.

        Returns:
            Validated rate limit string.

        Raises:
            ValueError: If format is invalid.
        """
        try:
            count, period = value.split('/')
            if not count.isdigit() or int(count) <= 0:
                raise ValueError("Rate limit count must be a positive integer.")
            if period not in ('second', 'minute', 'hour', 'day'):
                raise ValueError("Rate limit period must be second, minute, "
                                 "hour, or day.")
            return value
        except (ValueError, AttributeError) as e:
            logger.error(f"Invalid rate limit format: {value}. Error: {str(e)}")
            raise ValueError(f"Invalid rate limit format: {value}. "
                             f"Must be 'count/period'.")