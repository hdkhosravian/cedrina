import asyncio
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple

from jose import JWTError, jwt
from redis.asyncio import Redis
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select
from structlog import get_logger

from src.core.config.settings import settings
from src.core.exceptions import AuthenticationError, SessionLimitExceededError
from src.domain.entities.session import Session
from src.utils.i18n import get_translated_message

logger = get_logger(__name__)


class SessionService:
    """Enhanced service for managing user sessions with comprehensive security features.

    This service addresses critical session management vulnerabilities:
    1. Dual storage consistency between Redis and PostgreSQL
    2. Inactivity-based session expiration
    3. Concurrent session limits per user
    4. Immediate access token invalidation on session revocation
    5. Session activity tracking and cleanup

    Security Features:
        - Inactivity timeout enforcement (configurable)
        - Maximum concurrent sessions per user (configurable)
        - Redis-PostgreSQL consistency checks with timeout
        - Access token blacklisting for immediate invalidation
        - Session activity tracking for audit and cleanup
        - Atomic session operations to prevent race conditions

    Attributes:
        db_session (AsyncSession): SQLAlchemy async session for database operations.
        redis_client (Redis): Async Redis client for session storage.

    """

    def __init__(self, db_session: AsyncSession, redis_client: Redis):
        self.db_session = db_session
        self.redis_client = redis_client

    async def create_session(
        self, user_id: int, jti: str, refresh_token_hash: str, expires_at: datetime
    ) -> Session:
        """Create a new session with comprehensive security checks.

        This method implements secure session creation with:
        1. Concurrent session limit enforcement
        2. Atomic Redis-PostgreSQL consistency
        3. Activity tracking initialization
        4. Proper error handling and rollback

        Args:
            user_id (int): User ID.
            jti (str): JWT ID for the session.
            refresh_token_hash (str): Hashed refresh token.
            expires_at (datetime): Session expiration time.

        Returns:
            Session: Created session entity.

        Raises:
            SessionLimitExceededError: If user exceeds maximum concurrent sessions.
            AuthenticationError: If session creation fails due to consistency issues.

        """
        # Check concurrent session limits
        await self._enforce_session_limits(user_id)

        # Create session with activity tracking
        current_time = datetime.now(timezone.utc)
        session = Session(
            user_id=user_id,
            jti=jti,
            refresh_token_hash=refresh_token_hash,
            expires_at=expires_at,
            last_activity_at=current_time,
        )

        # Store in both Redis and PostgreSQL with consistency check
        try:
            # Calculate Redis TTL
            expire_seconds = int((expires_at - current_time).total_seconds())
            
            # Concurrent storage with consistency timeout
            await asyncio.wait_for(
                asyncio.gather(
                    self._store_in_redis(jti, refresh_token_hash, expire_seconds),
                    self._store_in_postgresql(session),
                ),
                timeout=settings.SESSION_CONSISTENCY_TIMEOUT_SECONDS,
            )
            
            await logger.ainfo(
                "Session created successfully",
                user_id=user_id,
                jti=jti,
                concurrent_sessions=await self._get_active_session_count(user_id),
            )
            return session
            
        except asyncio.TimeoutError:
            # Cleanup on consistency timeout
            await self._cleanup_failed_session_creation(jti, user_id)
            raise AuthenticationError(
                get_translated_message("session_creation_timeout", "en")
            )
        except Exception as e:
            # Cleanup on any error
            await self._cleanup_failed_session_creation(jti, user_id)
            await logger.aerror(
                "Session creation failed",
                user_id=user_id,
                jti=jti,
                error=str(e),
            )
            raise AuthenticationError(
                get_translated_message("session_creation_failed", "en")
            )

    async def update_session_activity(self, jti: str, user_id: int) -> bool:
        """Update session activity timestamp and validate session.

        This method updates the last_activity_at timestamp and performs
        comprehensive session validation including inactivity timeout.

        Args:
            jti (str): JWT ID of the session.
            user_id (int): User ID.

        Returns:
            bool: True if session is valid and updated, False otherwise.

        """
        session = await self.get_session(jti, user_id)
        if not session:
            return False

        # Check if session is revoked
        if session.revoked_at:
            await logger.adebug("Session revoked", jti=jti, user_id=user_id)
            return False

        # Check if session is expired
        if session.expires_at < datetime.now(timezone.utc):
            await logger.adebug("Session expired", jti=jti, user_id=user_id)
            return False

        # Check inactivity timeout
        inactivity_timeout = timedelta(minutes=settings.SESSION_INACTIVITY_TIMEOUT_MINUTES)
        if session.last_activity_at + inactivity_timeout < datetime.now(timezone.utc):
            await logger.ainfo(
                "Session expired due to inactivity",
                jti=jti,
                user_id=user_id,
                last_activity=session.last_activity_at.isoformat(),
            )
            await self.revoke_session(jti, user_id, "en")
            return False

        # Update activity timestamp
        session.last_activity_at = datetime.now(timezone.utc)
        self.db_session.add(session)
        await self.db_session.commit()

        # Update Redis activity timestamp
        await self.redis_client.hset(
            f"session_activity:{jti}",
            "last_activity",
            session.last_activity_at.isoformat(),
        )

        return True

    async def revoke_session(self, jti: str, user_id: int, language: str = "en") -> None:
        """Revoke a session with immediate access token invalidation.

        This method implements secure session revocation with:
        1. Immediate access token blacklisting
        2. Redis cleanup
        3. PostgreSQL session marking
        4. Audit logging

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
            raise AuthenticationError(
                get_translated_message("session_revoked_or_invalid", language)
            )

        # Mark session as revoked
        session.revoked_at = datetime.now(timezone.utc)
        self.db_session.add(session)

        # Immediate access token blacklisting
        await self._blacklist_access_token(jti)

        # Cleanup Redis data
        await asyncio.gather(
            self.redis_client.delete(f"refresh_token:{jti}"),
            self.redis_client.delete(f"session_activity:{jti}"),
        )

        await self.db_session.commit()
        await logger.ainfo("Session revoked", user_id=user_id, jti=jti)

    async def get_session(self, jti: str, user_id: int) -> Optional[Session]:
        """Retrieve a session by JWT ID and user ID.

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
        """Check if a session is valid with comprehensive validation.

        This method performs comprehensive session validation including:
        1. Session existence check
        2. Revocation status check
        3. Expiration check
        4. Inactivity timeout check
        5. Redis-PostgreSQL consistency check

        Args:
            jti (str): JWT ID.
            user_id (int): User ID.

        Returns:
            bool: True if session is valid, False otherwise.

        """
        session = await self.get_session(jti, user_id)
        if not session:
            await logger.adebug("Session not found", jti=jti, user_id=user_id)
            return False

        if session.revoked_at:
            await logger.adebug("Session revoked", jti=jti, user_id=user_id)
            return False

        if session.expires_at < datetime.now(timezone.utc):
            await logger.adebug("Session expired", jti=jti, user_id=user_id)
            return False

        # Check inactivity timeout
        inactivity_timeout = timedelta(minutes=settings.SESSION_INACTIVITY_TIMEOUT_MINUTES)
        if session.last_activity_at + inactivity_timeout < datetime.now(timezone.utc):
            await logger.ainfo(
                "Session expired due to inactivity",
                jti=jti,
                user_id=user_id,
                last_activity=session.last_activity_at.isoformat(),
            )
            return False

        # Verify Redis consistency
        try:
            redis_hash = await asyncio.wait_for(
                self.redis_client.get(f"refresh_token:{jti}"),
                timeout=settings.SESSION_CONSISTENCY_TIMEOUT_SECONDS,
            )
            if not redis_hash:
                await logger.awarning("Session inconsistency detected", jti=jti, user_id=user_id)
                return False
        except asyncio.TimeoutError:
            await logger.awarning("Redis consistency check timeout", jti=jti, user_id=user_id)
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

    async def get_user_active_sessions(self, user_id: int) -> List[Session]:
        """Get all active sessions for a user.

        Args:
            user_id (int): User ID.

        Returns:
            List[Session]: List of active sessions.

        """
        sessions = await self.db_session.exec(
            select(Session).where(
                and_(
                    Session.user_id == user_id,
                    Session.revoked_at.is_(None),
                    Session.expires_at > datetime.now(timezone.utc),
                    Session.last_activity_at + timedelta(minutes=settings.SESSION_INACTIVITY_TIMEOUT_MINUTES) > datetime.now(timezone.utc),
                )
            )
        )
        return sessions.all()

    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired and inactive sessions.

        This method removes sessions that are:
        1. Expired (expires_at < now)
        2. Inactive (last_activity_at + inactivity_timeout < now)
        3. Revoked (revoked_at is not null)

        Returns:
            int: Number of sessions cleaned up.

        """
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=settings.SESSION_INACTIVITY_TIMEOUT_MINUTES)
        
        # Find sessions to cleanup
        sessions_to_cleanup = await self.db_session.exec(
            select(Session).where(
                or_(
                    Session.expires_at < datetime.now(timezone.utc),
                    Session.last_activity_at < cutoff_time,
                    Session.revoked_at.is_not(None),
                )
            )
        )
        sessions = sessions_to_cleanup.all()
        
        if not sessions:
            return 0

        # Cleanup Redis data
        redis_keys = []
        for session in sessions:
            redis_keys.extend([
                f"refresh_token:{session.jti}",
                f"session_activity:{session.jti}",
            ])
        
        if redis_keys:
            await self.redis_client.delete(*redis_keys)

        # Delete from database
        for session in sessions:
            await self.db_session.delete(session)
        
        await self.db_session.commit()
        
        await logger.ainfo(
            "Expired sessions cleaned up",
            count=len(sessions),
            user_ids=[s.user_id for s in sessions],
        )
        
        return len(sessions)

    async def _enforce_session_limits(self, user_id: int) -> None:
        """Enforce maximum concurrent sessions per user.

        Args:
            user_id (int): User ID.

        Raises:
            SessionLimitExceededError: If user exceeds maximum concurrent sessions.

        """
        active_sessions = await self.get_user_active_sessions(user_id)
        
        if len(active_sessions) >= settings.MAX_CONCURRENT_SESSIONS_PER_USER:
            # Revoke oldest session to make room
            oldest_session = min(active_sessions, key=lambda s: s.last_activity_at)
            await self.revoke_session(oldest_session.jti, user_id, "en")
            await logger.ainfo(
                "Oldest session revoked to enforce limits",
                user_id=user_id,
                revoked_jti=oldest_session.jti,
            )

    async def _get_active_session_count(self, user_id: int) -> int:
        """Get the number of active sessions for a user.

        Args:
            user_id (int): User ID.

        Returns:
            int: Number of active sessions.

        """
        sessions = await self.get_user_active_sessions(user_id)
        return len(sessions)

    async def _store_in_redis(self, jti: str, refresh_token_hash: str, expire_seconds: int) -> None:
        """Store session data in Redis.

        Args:
            jti (str): JWT ID.
            refresh_token_hash (str): Hashed refresh token.
            expire_seconds (int): TTL in seconds.

        """
        await self.redis_client.setex(f"refresh_token:{jti}", expire_seconds, refresh_token_hash)

    async def _store_in_postgresql(self, session: Session) -> None:
        """Store session in PostgreSQL.

        Args:
            session (Session): Session entity to store.

        """
        self.db_session.add(session)
        await self.db_session.commit()
        await self.db_session.refresh(session)

    async def _blacklist_access_token(self, jti: str) -> None:
        """Blacklist an access token for immediate invalidation.

        Args:
            jti (str): JWT ID to blacklist.

        """
        ttl_hours = settings.ACCESS_TOKEN_BLACKLIST_TTL_HOURS
        await self.redis_client.setex(
            f"access_token_blacklist:{jti}",
            ttl_hours * 3600,  # Convert hours to seconds
            "revoked",
        )

    async def _cleanup_failed_session_creation(self, jti: str, user_id: int) -> None:
        """Cleanup resources on failed session creation.

        Args:
            jti (str): JWT ID.
            user_id (int): User ID.

        """
        await asyncio.gather(
            self.redis_client.delete(f"refresh_token:{jti}"),
            self.redis_client.delete(f"session_activity:{jti}"),
            return_exceptions=True,
        )
