import asyncio
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any, Mapping, Optional

from jwt import encode as jwt_encode, decode as jwt_decode, PyJWTError
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from structlog import get_logger

from src.core.config.settings import settings
from src.core.exceptions import AuthenticationError
from src.domain.entities.user import User
from src.domain.services.auth.session import SessionService
from src.domain.value_objects.jwt_token import TokenId
from src.utils.i18n import get_translated_message
from src.core.logging import logger

logger = get_logger(__name__)


class TokenService:
    """Service for managing JWT access and refresh tokens.

    Handles token creation, validation, and refresh with RS256 signing, integrating
    with PostgreSQL and Redis for session tracking and security. This service ensures
    secure token management by using asymmetric encryption (RS256), token expiration,
    and secure storage of refresh tokens to prevent unauthorized access.

    Attributes:
        db_session (AsyncSession): SQLAlchemy async session for database operations.
        redis_client (Redis): Async Redis client for token storage.
        session_service (SessionService): Service for managing user sessions.

    """

    def __init__(
        self,
        db_session: AsyncSession,
        redis_client: Redis,
        session_service: Optional[SessionService] = None,
    ):
        self.db_session = db_session
        self.redis_client = redis_client
        self.session_service = session_service or SessionService(db_session, redis_client)

    async def create_access_token(self, user: User) -> str:
        """Create a JWT access token with enhanced security.

        Args:
            user (User): User for whom to create the token.

        Returns:
            str: Encoded JWT access token with enhanced JTI security.

        Note:
            Uses enhanced TokenId generation for improved cryptographic security
            and collision resistance. The JTI now provides 256 bits of entropy
            instead of the previous 192 bits.
        """
        # Generate enhanced secure JTI
        token_id = TokenId.generate()
        
        payload = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "exp": datetime.now(timezone.utc)
            + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
            "iat": datetime.now(timezone.utc),
            "jti": str(token_id),
        }
        token = jwt_encode(payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256")
        logger.debug("Access token created", user_id=user.id, jti=token_id.mask_for_logging())
        return token

    async def create_refresh_token(self, user: User, jti: Optional[str] = None) -> str:
        """Create a JWT refresh token and store in Redis/PostgreSQL.

        Args:
            user (User): User for whom to create the token.
            jti (str): JWT ID for the refresh token. If None, generates enhanced secure JTI.

        Returns:
            str: Encoded JWT refresh token.

        Note:
            Refresh tokens are stored as hashes in Redis and PostgreSQL to prevent theft.
            The token expiration is set to a longer duration than access tokens, and token
            rotation is implemented during refresh to enhance security.
            Uses enhanced TokenId generation for improved cryptographic security.
        """
        # Auto-generate a new enhanced secure JTI if the caller did not supply one
        if jti is None:
            token_id = TokenId.generate()
            jti = str(token_id)
        else:
            # Validate provided JTI
            token_id = TokenId(jti)

        payload = {
            "sub": str(user.id),
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "exp": datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            "iat": datetime.now(timezone.utc),
            "jti": jti,
        }
        refresh_token = jwt_encode(
            payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256"
        )
        refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

        # Store in Redis and DB concurrently
        expire_seconds = int(timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS).total_seconds())

        await asyncio.gather(
            self.redis_client.setex(self._redis_key(jti), expire_seconds, refresh_token_hash),
            self.session_service.create_session(user.id, jti, refresh_token_hash, payload["exp"]),
        )

        logger.debug("Refresh token created", user_id=user.id, jti=token_id.mask_for_logging())
        return refresh_token

    async def refresh_tokens(self, refresh_token: str, language: str = "en") -> Mapping[str, str]:
        """Refresh JWT tokens using a refresh token with rotation.

        Args:
            refresh_token (str): Current refresh token.
            language (str): Language for error messages (defaults to 'en').

        Returns:
            Mapping[str, str]: New access and refresh tokens with metadata.

        Raises:
            AuthenticationError: If refresh token is invalid or revoked.

        Note:
            Implements token rotation by revoking the old refresh token and issuing a new one,
            reducing the risk of token theft. Validates token signature, issuer, audience, and
            checks for revocation in both Redis and PostgreSQL. Now includes session activity
            tracking and enhanced validation.

        """
        try:
            payload = jwt_decode(
                refresh_token,
                settings.JWT_PUBLIC_KEY,
                algorithms=["RS256"],
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE,
            )
            jti = payload["jti"]
            user_id = int(payload["sub"])

            # Verify in Redis
            stored_hash = await self.redis_client.get(self._redis_key(jti))
            if (
                not stored_hash
                or stored_hash.decode() != hashlib.sha256(refresh_token.encode()).hexdigest()
            ):
                logger.warning("Invalid refresh token", jti=jti)
                raise AuthenticationError(get_translated_message("invalid_refresh_token", language))

            # Enhanced session validation with activity tracking
            if not await self.session_service.is_session_valid(jti, user_id):
                logger.warning("Invalid session during token refresh", jti=jti)
                raise AuthenticationError(
                    get_translated_message("session_revoked_or_invalid", language)
                )

            # Update session activity
            if not await self.session_service.update_session_activity(jti, user_id):
                logger.warning("Session activity update failed", jti=jti)
                raise AuthenticationError(
                    get_translated_message("session_revoked_or_invalid", language)
                )

            # Get user
            user = await self.db_session.get(User, user_id)
            if not user or not user.is_active:
                logger.warning("Inactive user refresh attempt", user_id=user_id)
                raise AuthenticationError(get_translated_message("user_account_inactive", language))

            # Revoke old session & rotate token concurrently
            await self.session_service.revoke_session(jti, user_id, language)

            # Create new tokens
            new_token_id = TokenId.generate()
            access_token = await self.create_access_token(user)
            refresh_token = await self.create_refresh_token(user, str(new_token_id))
            logger.info("Tokens refreshed", user_id=user_id, new_jti=new_token_id.mask_for_logging())
            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            }
        except PyJWTError as e:
            logger.error("JWT decode failed", error=str(e))
            raise AuthenticationError(get_translated_message("invalid_refresh_token", language))

    async def validate_token(self, token: str, language: str = "en") -> Mapping[str, Any]:
        """Validate a JWT access token with advanced checks.

        Args:
            token (str): JWT access token.
            language (str): Language for error messages (defaults to 'en').

        Returns:
            Mapping[str, Any]: Decoded payload.

        Raises:
            AuthenticationError: If token is invalid, expired, or user is inactive.

        Note:
            Validates token signature, issuer, audience, and expiration. Additionally,
            checks if the associated user is active to prevent access by deactivated accounts.
            Now includes enhanced session validation and access token blacklist checking.

        """
        try:
            payload = jwt_decode(
                token,
                settings.JWT_PUBLIC_KEY,
                algorithms=["RS256"],
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE,
            )
            user_id = int(payload["sub"])
            jti = payload["jti"]

            # Concurrently check if token blacklisted and fetch user details.
            blacklisted_task = asyncio.create_task(self._is_token_blacklisted(jti))
            user_task = asyncio.create_task(self.db_session.get(User, user_id))

            blacklisted, user = await asyncio.gather(blacklisted_task, user_task)

            if blacklisted:
                logger.warning("Blacklisted token used", jti=jti, user_id=user_id)
                raise AuthenticationError(
                    get_translated_message("token_revoked_or_blacklisted", language)
                )

            if not user or not user.is_active:
                logger.warning("Invalid user in JWT", user_id=user_id)
                raise AuthenticationError(
                    get_translated_message("user_is_invalid_or_inactive", language)
                )

            # Enhanced session validation for access tokens
            if not await self.session_service.is_session_valid(jti, user_id):
                logger.warning("Invalid session during token validation", jti=jti, user_id=user_id)
                raise AuthenticationError(
                    get_translated_message("session_revoked_or_invalid", language)
                )

            logger.debug("JWT validated", user_id=user_id, jti=jti)
            return payload
        except PyJWTError as e:
            logger.error("JWT validation failed", error=str(e))
            raise AuthenticationError(get_translated_message("invalid_token", language)) from e

    async def _is_token_blacklisted(self, jti: str) -> bool:
        """Check if a token's JTI is blacklisted.

        Args:
            jti (str): JWT ID to check.

        Returns:
            bool: True if blacklisted, False otherwise.

        Note:
            This is a placeholder for implementing a token blacklist mechanism, which could
            use Redis or a database table to store revoked or compromised token JTIs. For
            high-security applications, consider implementing this to handle token revocation
            beyond session management.

        """
        key = self._blacklist_key(jti)
        value = await self.redis_client.get(key)
        return value == "revoked"

    async def revoke_refresh_token(self, encoded_token: str, language: str = "en") -> None:
        """Revoke a refresh token.

        Args:
            encoded_token (str): Encoded refresh token.
            language (str): Language for error messages (defaults to 'en').

        Raises:
            AuthenticationError: If token is invalid.

        Note:
            Ensures the token is validated before revocation and removes it from both
            Redis and PostgreSQL storage to prevent further use.

        """
        await self.session_service.revoke_token(encoded_token, language)

    async def revoke_access_token(self, jti: str, expires_in: int | None = None) -> None:
        """Revoke (blacklist) an access-token by its *JTI*.

        The JTI is stored in Redis with a TTL equal to the remaining lifespan of
        the original access token (defaults to ``ACCESS_TOKEN_EXPIRE_MINUTES``).

        Args:
            jti: The JWT ID of the access token to revoke.
            expires_in: Optional number of seconds to keep the blacklist entry.
                       If *None*, we use the configured access-token lifetime.

        """
        if expires_in is None:
            expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

        await self.redis_client.setex(self._blacklist_key(jti), expires_in, "revoked")
        logger.info("Access token revoked", jti=jti, ttl=expires_in)

    @staticmethod
    def _redis_key(jti: str) -> str:
        """Generate the Redis key under which the refresh-token hash is stored."""
        return f"refresh_token:{jti}"

    @staticmethod
    def _blacklist_key(jti: str) -> str:
        """Return the Redis key under which a blacklisted JTI is stored."""
        return f"blacklist:{jti}"
