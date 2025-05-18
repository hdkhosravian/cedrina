import pytest
import pytest_asyncio
from unittest.mock import AsyncMock
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis
from datetime import datetime, timezone, timedelta

from src.domain.entities.session import Session
from src.domain.services.auth.session import SessionService
from src.core.exceptions import AuthenticationError

@pytest_asyncio.fixture
async def db_session():
    return AsyncMock(spec=AsyncSession)

@pytest_asyncio.fixture
async def redis_client():
    return AsyncMock(spec=Redis)

@pytest_asyncio.fixture
def session_service(db_session, redis_client):
    return SessionService(db_session, redis_client)

@pytest.mark.asyncio
async def test_create_session(session_service, db_session):
    # Arrange
    user_id = 1
    jti = "test-jti"
    refresh_token_hash = "hashed_token"
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    # Act
    session = await session_service.create_session(user_id, jti, refresh_token_hash, expires_at)

    # Assert
    assert session.user_id == user_id
    assert session.jti == jti
    assert session.refresh_token_hash == refresh_token_hash
    assert session.expires_at == expires_at
    db_session.add.assert_called_once()
    db_session.commit.assert_called_once()
    db_session.refresh.assert_called_once()

@pytest.mark.asyncio
async def test_revoke_session_success(session_service, db_session, redis_client):
    # Arrange
    user_id = 1
    jti = "test-jti"
    session = Session(user_id=user_id, jti=jti, refresh_token_hash="hashed_token")
    db_session.exec.return_value.first.return_value = session

    # Act
    await session_service.revoke_session(jti, user_id)

    # Assert
    assert session.revoked_at is not None
    db_session.add.assert_called_once()
    redis_client.delete.assert_called_once_with(f"refresh_token:{jti}")
    db_session.commit.assert_called_once()

@pytest.mark.asyncio
async def test_revoke_session_already_revoked(session_service, db_session):
    # Arrange
    user_id = 1
    jti = "test-jti"
    session = Session(
        user_id=user_id,
        jti=jti,
        refresh_token_hash="hashed_token",
        revoked_at=datetime.now(timezone.utc)
    )
    db_session.exec.return_value.first.return_value = session

    # Act/Assert
    with pytest.raises(AuthenticationError, match="Session already revoked or invalid"):
        await session_service.revoke_session(jti, user_id)

@pytest.mark.asyncio
async def test_is_session_valid_valid(session_service, db_session):
    # Arrange
    user_id = 1
    jti = "test-jti"
    session = Session(
        user_id=user_id,
        jti=jti,
        refresh_token_hash="hashed_token",
        expires_at=datetime.now(timezone.utc) + timedelta(days=1)
    )
    db_session.exec.return_value.first.return_value = session

    # Act
    is_valid = await session_service.is_session_valid(jti, user_id)

    # Assert
    assert is_valid is True

@pytest.mark.asyncio
async def test_is_session_valid_expired(session_service, db_session):
    # Arrange
    user_id = 1
    jti = "test-jti"
    session = Session(
        user_id=user_id,
        jti=jti,
        refresh_token_hash="hashed_token",
        expires_at=datetime.now(timezone.utc) - timedelta(days=1)
    )
    db_session.exec.return_value.first.return_value = session

    # Act
    is_valid = await session_service.is_session_valid(jti, user_id)

    # Assert
    assert is_valid is False