"""Authentication and authorization settings.
"""

import logging
from pathlib import Path

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class AuthSettings(BaseSettings):
    """Defines settings for authentication, including OAuth providers and JWT configuration.
    It handles loading JWT keys from PEM files or environment variables.

    Security Note:
        - JWT keys must be securely stored and rotated regularly to prevent token forgery
          (OWASP A02:2021 - Cryptographic Failures).
        - OAuth client secrets should never be exposed in logs or version control.
        - Ensure PEM files are readable only by the application user (chmod 600) to prevent
          unauthorized access to private keys.
    """

    # OAuth settings
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: SecretStr = SecretStr("")
    MICROSOFT_CLIENT_ID: str = ""
    MICROSOFT_CLIENT_SECRET: SecretStr = SecretStr("")
    FACEBOOK_CLIENT_ID: str = ""
    FACEBOOK_CLIENT_SECRET: SecretStr = SecretStr("")

    # JWT settings
    JWT_PRIVATE_KEY: SecretStr = SecretStr("")
    JWT_PUBLIC_KEY: str = ""
    JWT_ISSUER: str = "https://api.example.com"
    JWT_AUDIENCE: str = "cedrina:api:v1"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Email confirmation feature flag
    EMAIL_CONFIRMATION_ENABLED: bool = False

    # Session management security settings
    SESSION_INACTIVITY_TIMEOUT_MINUTES: int = 30  # Session expires after 30 minutes of inactivity
    MAX_CONCURRENT_SESSIONS_PER_USER: int = 5  # Maximum active sessions per user
    SESSION_CONSISTENCY_TIMEOUT_SECONDS: int = 5  # Timeout for Redis-PostgreSQL consistency checks
    ACCESS_TOKEN_BLACKLIST_TTL_HOURS: int = 24  # How long to keep revoked access tokens in blacklist

    @model_validator(mode="after")
    def _load_and_validate_jwt_keys(self) -> "AuthSettings":
        """Loads JWT keys, prioritizing .pem files over environment variables.
        Raises ValueError if keys are not found, ensuring secure configuration.

        Returns:
            Self instance with loaded keys.

        """
        self._load_keys_from_pem_files()

        if not self.JWT_PRIVATE_KEY.get_secret_value() or not self.JWT_PUBLIC_KEY:
            error_msg = (
                "JWT keys not found. Please provide JWT_PRIVATE_KEY and JWT_PUBLIC_KEY "
                "either via .env variables or through private.pem/public.pem files."
            )
            logger.error(error_msg)
            raise ValueError(error_msg)

        logger.info("JWT keys validated successfully.")
        return self

    def _load_keys_from_pem_files(self) -> None:
        """Loads JWT keys from private.pem and public.pem if they exist.
        These files will override any existing environment variables.
        Ensures secure file handling to prevent path traversal or unauthorized access.
        """
        private_key_path = Path("private.pem")
        public_key_path = Path("public.pem")

        # Security: Ensure paths are absolute to prevent traversal attacks
        private_key_path = private_key_path.resolve()
        public_key_path = public_key_path.resolve()

        if private_key_path.is_file():
            try:
                private_key = private_key_path.read_text().strip()
                if private_key:
                    self.JWT_PRIVATE_KEY = SecretStr(private_key)
                    logger.info(
                        "Loaded JWT private key from private.pem, overriding env var if set."
                    )
            except Exception as e:
                logger.error(f"Failed to read private.pem: {e!s}")

        if public_key_path.is_file():
            try:
                public_key = public_key_path.read_text().strip()
                if public_key:
                    self.JWT_PUBLIC_KEY = public_key
                    logger.info("Loaded JWT public key from public.pem, overriding env var if set.")
            except Exception as e:
                logger.error(f"Failed to read public.pem: {e!s}")
