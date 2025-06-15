"""
Authentication and authorization settings.
"""
import logging
from pathlib import Path
from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class AuthSettings(BaseSettings):
    """
    Defines settings for authentication, including OAuth providers and JWT configuration.
    It handles loading JWT keys from PEM files or environment variables.
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

    @model_validator(mode='after')
    def _load_and_validate_jwt_keys(self) -> 'AuthSettings':
        """
        Loads JWT keys, prioritizing .pem files over environment variables.
        """
        self._load_keys_from_pem_files()

        if not self.JWT_PRIVATE_KEY.get_secret_value() or not self.JWT_PUBLIC_KEY:
            error_msg = (
                "JWT keys not found. Please provide JWT_PRIVATE_KEY and JWT_PUBLIC_KEY "
                "either via .env variables or through private.pem/public.pem files."
            )
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        return self

    def _load_keys_from_pem_files(self):
        """
        Loads JWT keys from private.pem and public.pem if they exist.
        These files will override any existing environment variables.
        """
        private_key_path = Path("private.pem")
        public_key_path = Path("public.pem")

        if private_key_path.is_file():
            try:
                private_key = private_key_path.read_text().strip()
                if private_key:
                    self.JWT_PRIVATE_KEY = SecretStr(private_key)
                    logger.info("Loaded JWT private key from private.pem, overriding env var if set.")
            except Exception as e:
                logger.warning("Failed to load private key from private.pem: %s", e)
        
        if public_key_path.is_file():
            try:
                public_key = public_key_path.read_text().strip()
                if public_key:
                    self.JWT_PUBLIC_KEY = public_key
                    logger.info("Loaded JWT public key from public.pem, overriding env var if set.")
            except Exception as e:
                logger.warning("Failed to load public key from public.pem: %s", e) 