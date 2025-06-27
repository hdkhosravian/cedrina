from datetime import datetime, timezone, timedelta
from typing import Optional
from uuid import UUID

from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis
from sqlmodel import select
from structlog import get_logger

from src.core.config.settings import settings

from src.domain.entities.session import Session
from src.core.exceptions import AuthenticationError
from src.utils.i18n import get_translated_message

logger = get_logger(__name__)

class SessionService:
    """
    Service for managing user sessions and refresh token revocation.

    Tracks sessions in PostgreSQL and Redis, supporting token rotation and revocation.

    Attributes:
        db_session (AsyncSession): SQLAlchemy async session for database operations.
        redis_client (Redis): Async Redis client for session storage.
    """

    def __init__(self, db_session: AsyncSession, redis_client: Redis):
        self.db_session = db_session
        self.redis_client = redis_client

    async def create_session(self, user_id: int, jti: str, refresh_token_hash: str, expires_at: datetime) -> Session:
        """
        Create a new session for a user.

        Args:
            user_id (int): User ID.
            jti (str): JWT ID for the session.
            refresh_token_hash (str): Hashed refresh token.
            expires_at (datetime): Session expiration time.

        Returns:
            Session: Created session entity.
        """
        session = Session(
            user_id=user_id,
            jti=jti,
            refresh_token_hash=refresh_token_hash,
            expires_at=expires_at,
        )
        self.db_session.add(session)
        await self.db_session.commit()
        await self.db_session.refresh(session)
        await logger.adebug("Session created", user_id=user_id, jti=jti)
        return session

    async def revoke_session(self, jti: str, user_id: int, language: str = "en") -> None:
        """
        Revoke a session by marking it as inactive.

        Args:
            jti (str): JWT ID of the session.
            user_id (int): User ID.
            language (str): Language code for error messages. Defaults to "en".

        Raises:
            AuthenticationError: If session is invalid or already revoked.
        """
        session = await self.get_session(jti, user_id)
        if not session or session.revoked_at:
            await logger.awarning("Attempt to revoke invalid session", jti=jti)
            raise AuthenticationError(get_translated_message("session_revoked_or_invalid", language))

        session.revoked_at = datetime.now(timezone.utc)
        self.db_session.add(session)
        await self.redis_client.delete(f"refresh_token:{jti}")
        await self.db_session.commit()
        await logger.ainfo("Session revoked", user_id=user_id, jti=jti)

    async def get_session(self, jti: str, user_id: int) -> Optional[Session]:
        """
        Retrieve a session by JWT ID and user ID.

        Args:
            jti (str): JWT ID.
            user_id (int): User ID.

        Returns:
            Optional[Session]: Session entity or None if not found.
        """
        session = await self.db_session.exec(
            select(Session).where(Session.jti == jti, Session.user_id == user_id)
        )
        return session.first()

    async def is_session_valid(self, jti: str, user_id: int) -> bool:
        """
        Check if a session is valid (not revoked or expired).

        Args:
            jti (str): JWT ID.
            user_id (int): User ID.

        Returns:
            bool: True if session is valid, False otherwise.
        """
        session = await self.get_session(jti, user_id)
        if not session or session.revoked_at or session.expires_at < datetime.now(timezone.utc):
            await logger.adebug("Invalid session", jti=jti, user_id=user_id)
            return False
        return True

    async def revoke_token(self, encoded_token: str, language: str = "en") -> None:
        """Decode a refresh token and revoke the associated session."""

        try:
            payload = jwt.decode(
                encoded_token,
                settings.JWT_PUBLIC_KEY,
                algorithms=["RS256"],
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE,
            )
            jti = payload["jti"]
            user_id = int(payload["sub"])
        except JWTError as exc:  # pragma: no cover - error path
            raise AuthenticationError(
                get_translated_message("invalid_refresh_token", language)
            ) from exc

        await self.revoke_session(jti, user_id, language)
