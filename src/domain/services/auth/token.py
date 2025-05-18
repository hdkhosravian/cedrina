from datetime import datetime, timedelta, timezone
from typing import Dict, Any
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis
from structlog import get_logger
import secrets
import hashlib

from src.domain.entities.user import User
from src.core.config import settings
from src.core.exceptions import AuthenticationError

logger = get_logger(__name__)

class TokenService:
    """
    Service for managing JWT access and refresh tokens.

    Handles token creation, validation, and refresh with RS256 signing, integrating
    with PostgreSQL and Redis for session tracking and security.

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
        token = jwt.encode(payload, settings.JWT_PRIVATE_KEY, algorithm="RS256")
        await logger.debug("Access token created", user_id=user.id, jti=payload["jti"])
        return token

    async def create_refresh_token(self, user: User, jti: str) -> str:
        """
        Create a JWT refresh token and store in Redis/PostgreSQL.

        Args:
            user (User): User for whom to create the token.
            jti (str): JWT ID for the refresh token.

        Returns:
            str: Encoded JWT refresh token.
        """
        from src.domain.services.auth.session import SessionService  # Avoid circular import
        payload = {
            "sub": str(user.id),
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "exp": datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            "iat": datetime.now(timezone.utc),
            "jti": jti
        }
        refresh_token = jwt.encode(payload, settings.JWT_PRIVATE_KEY, algorithm="RS256")
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

        await logger.debug("Refresh token created", user_id=user.id, jti=jti)
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
        """
        from src.domain.services.auth.session import SessionService  # Avoid circular import
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
                await logger.warning("Invalid refresh token", jti=jti)
                raise AuthenticationError("Invalid refresh token")

            # Verify session
            session_service = SessionService(self.db_session, self.redis_client)
            session = await session_service.get_session(jti, user_id)
            if not session or session.revoked_at:
                await logger.warning("Revoked or invalid session", jti=jti)
                raise AuthenticationError("Session revoked or invalid")

            # Get user
            user = await self.db_session.get(User, user_id)
            if not user or not user.is_active:
                await logger.warning("Inactive user refresh attempt", user_id=user_id)
                raise AuthenticationError("User account is inactive")

            # Revoke old session
            await session_service.revoke_session(jti, user_id)

            # Create new tokens
            new_jti = secrets.token_urlsafe(16)
            access_token = await self.create_access_token(user)
            refresh_token = await self.create_refresh_token(user, new_jti)
            await logger.info("Tokens refreshed", user_id=user_id, new_jti=new_jti)
            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            }
        except JWTError as e:
            await logger.error("JWT decode failed", error=str(e))
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

            # Check user
            user = await self.db_session.get(User, user_id)
            if not user or not user.is_active:
                await logger.warning("Invalid user in JWT", user_id=user_id)
                raise AuthenticationError("User is invalid or inactive")

            await logger.debug("JWT validated", user_id=user_id, jti=payload["jti"])
            return payload
        except JWTError as e:
            await logger.error("JWT validation failed", error=str(e))
            raise AuthenticationError("Invalid token")