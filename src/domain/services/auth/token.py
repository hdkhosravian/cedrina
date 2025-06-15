from datetime import datetime, timedelta, timezone
from typing import Dict, Any
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis
from structlog import get_logger
import secrets
import hashlib
from pydantic import ValidationError

from domain.entities.user import User
from core.config.settings import settings
from core.exceptions import AuthenticationError

logger = get_logger(__name__)

class TokenService:
    """
    Service for managing JWT access and refresh tokens.

    Handles token creation, validation, and refresh with RS256 signing, integrating
    with PostgreSQL and Redis for session tracking and security. This service ensures
    secure token management by using asymmetric encryption (RS256), token expiration,
    and secure storage of refresh tokens to prevent unauthorized access.

    Attributes:
        db_session (AsyncSession): SQLAlchemy async session for database operations.
        redis_client (Redis): Async Redis client for token storage.
    """

    def __init__(self, db_session: AsyncSession, redis_client: Redis):
        self.db_session = db_session
        self.redis_client = redis_client

    async def create_access_token(self, user: User) -> str:
        """
        Create a JWT access token with advanced claims.

        Args:
            user (User): User for whom to create the token.

        Returns:
            str: Encoded JWT access token.

        Note:
            Uses RS256 (RSA with SHA-256) for signing, which is more secure than symmetric
            algorithms like HS256 as it uses a private-public key pair. The token includes
            claims like subject (sub), issuer (iss), audience (aud), and a unique JWT ID (jti)
            to prevent replay attacks.
        """
        payload = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
            "iat": datetime.now(timezone.utc),
            "jti": secrets.token_urlsafe(16)
        }
        token = jwt.encode(payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256")
        logger.debug("Access token created", user_id=user.id, jti=payload["jti"])
        return token

    async def create_refresh_token(self, user: User, jti: str) -> str:
        """
        Create a JWT refresh token and store in Redis/PostgreSQL.

        Args:
            user (User): User for whom to create the token.
            jti (str): JWT ID for the refresh token.

        Returns:
            str: Encoded JWT refresh token.

        Note:
            Refresh tokens are stored as hashes in Redis and PostgreSQL to prevent theft.
            The token expiration is set to a longer duration than access tokens, and token
            rotation is implemented during refresh to enhance security.
        """
        from domain.services.auth.session import SessionService  # Avoid circular import
        payload = {
            "sub": str(user.id),
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "exp": datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            "iat": datetime.now(timezone.utc),
            "jti": jti
        }
        refresh_token = jwt.encode(payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256")
        refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

        # Store in Redis
        await self.redis_client.setex(
            f"refresh_token:{jti}",
            int(timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS).total_seconds()),
            refresh_token_hash
        )

        # Store in PostgreSQL via SessionService
        session_service = SessionService(self.db_session, self.redis_client)
        await session_service.create_session(user.id, jti, refresh_token_hash, payload["exp"])

        logger.debug("Refresh token created", user_id=user.id, jti=jti)
        return refresh_token

    async def refresh_tokens(self, refresh_token: str) -> Dict[str, str]:
        """
        Refresh JWT tokens using a refresh token with rotation.

        Args:
            refresh_token (str): Current refresh token.

        Returns:
            Dict[str, str]: New access and refresh tokens with metadata.

        Raises:
            AuthenticationError: If refresh token is invalid or revoked.

        Note:
            Implements token rotation by revoking the old refresh token and issuing a new one,
            reducing the risk of token theft. Validates token signature, issuer, audience, and
            checks for revocation in both Redis and PostgreSQL.
        """
        from domain.services.auth.session import SessionService  # Avoid circular import
        try:
            payload = jwt.decode(
                refresh_token,
                settings.JWT_PUBLIC_KEY,
                algorithms=["RS256"],
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE
            )
            jti = payload["jti"]
            user_id = int(payload["sub"])

            # Verify in Redis
            stored_hash = await self.redis_client.get(f"refresh_token:{jti}")
            if not stored_hash or stored_hash.decode() != hashlib.sha256(refresh_token.encode()).hexdigest():
                logger.warning("Invalid refresh token", jti=jti)
                raise AuthenticationError("Invalid refresh token")

            # Verify session
            session_service = SessionService(self.db_session, self.redis_client)
            session = await session_service.get_session(jti, user_id)
            if not session or session.revoked_at:
                logger.warning("Revoked or invalid session", jti=jti)
                raise AuthenticationError("Session revoked or invalid")

            # Get user
            user = await self.db_session.get(User, user_id)
            if not user or not user.is_active:
                logger.warning("Inactive user refresh attempt", user_id=user_id)
                raise AuthenticationError("User account is inactive")

            # Revoke old session
            await session_service.revoke_session(jti, user_id)

            # Create new tokens
            new_jti = secrets.token_urlsafe(16)
            access_token = await self.create_access_token(user)
            refresh_token = await self.create_refresh_token(user, new_jti)
            logger.info("Tokens refreshed", user_id=user_id, new_jti=new_jti)
            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            }
        except JWTError as e:
            logger.error("JWT decode failed", error=str(e))
            raise AuthenticationError("Invalid refresh token")

    async def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate a JWT access token with advanced checks.

        Args:
            token (str): JWT access token.

        Returns:
            Dict[str, Any]: Decoded payload.

        Raises:
            AuthenticationError: If token is invalid, expired, or user is inactive.

        Note:
            Validates token signature, issuer, audience, and expiration. Additionally,
            checks if the associated user is active to prevent access by deactivated accounts.
        """
        try:
            payload = jwt.decode(
                token,
                settings.JWT_PUBLIC_KEY,
                algorithms=["RS256"],
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE
            )
            user_id = int(payload["sub"])

            # Check if token is blacklisted (e.g., due to compromise)
            if await self._is_token_blacklisted(payload["jti"]):
                logger.warning("Blacklisted token used", jti=payload["jti"], user_id=user_id)
                raise AuthenticationError("Token has been revoked or blacklisted")

            # Check user
            user = await self.db_session.get(User, user_id)
            if not user or not user.is_active:
                logger.warning("Invalid user in JWT", user_id=user_id)
                raise AuthenticationError("User is invalid or inactive")

            logger.debug("JWT validated", user_id=user_id, jti=payload["jti"])
            return payload
        except JWTError as e:
            logger.error("JWT validation failed", error=str(e))
            raise AuthenticationError("Invalid token")

    async def _is_token_blacklisted(self, jti: str) -> bool:
        """
        Check if a token's JTI is blacklisted.

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
        # Placeholder: Implement actual blacklist check if needed
        return False

    def _get_session_service(self) -> "SessionService":
        """Get SessionService to avoid circular import."""
        from domain.services.auth.session import SessionService  # Avoid circular import
        return SessionService(self.db_session, self.redis_client)

    async def revoke_refresh_token(self, encoded_token: str) -> None:
        """
        Revoke a refresh token.

        Args:
            encoded_token (str): Encoded refresh token.

        Raises:
            AuthenticationError: If the token is invalid or cannot be revoked.

        Note:
            Ensures the token is validated before revocation and removes it from both
            Redis and PostgreSQL storage to prevent further use.
        """
        try:
            payload = jwt.decode(
                encoded_token,
                settings.JWT_PUBLIC_KEY,
                algorithms=["RS256"],
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE
            )
            jti = payload["jti"]
            user_id = int(payload["sub"])

            # Verify in Redis
            stored_hash = await self.redis_client.get(f"refresh_token:{jti}")
            if not stored_hash or stored_hash.decode() != hashlib.sha256(encoded_token.encode()).hexdigest():
                logger.warning("Invalid refresh token", jti=jti)
                raise AuthenticationError("Invalid refresh token")

            # Verify session
            session_service = self._get_session_service()
            session = await session_service.get_session(jti, user_id)
            if not session or session.revoked_at:
                logger.warning("Revoked or invalid session", jti=jti)
                raise AuthenticationError("Session revoked or invalid")

            # Revoke session
            await session_service.revoke_session(jti, user_id)
        except (JWTError, ValidationError, AuthenticationError) as e:
            logger.warning("Invalid refresh token", error=str(e))
            raise AuthenticationError("Invalid refresh token")

    def _get_session_service_sync(self) -> "SessionService":
        """Get SessionService to avoid circular import."""
        from domain.services.auth.session import SessionService  # Avoid circular import
        return SessionService(self.db_session, self.redis_client)