import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from redis.asyncio import Redis
from sqlmodel import SQLModel
from httpx import AsyncClient
from jose import jwt
from datetime import datetime, timezone, timedelta

from src.domain.entities.user import User, Role
from src.domain.entities.oauth_profile import OAuthProfile, Provider
from src.domain.entities.session import Session
from src.domain.services.auth.user_authentication import UserAuthenticationService
from src.domain.services.auth.token import TokenService
from src.domain.services.auth.session import SessionService
from src.core.config import settings
from src.core.exceptions import AuthenticationError

@pytest_asyncio.fixture
async def db_session():
    engine = create_async_engine(settings.DATABASE_URL.replace("postgresql+psycopg2", "postgresql+asyncpg"))
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
    await engine.dispose()

@pytest_asyncio.fixture
async def redis_client():
    redis = Redis.from_url(settings.REDIS_URL)
    yield redis
    await redis.flushdb()
    await redis.close()

@pytest_asyncio.fixture
async def user_auth_service(db_session):
    return UserAuthenticationService(db_session)

@pytest_asyncio.fixture
async def token_service(db_session, redis_client):
    return TokenService(db_session, redis_client)

@pytest_asyncio.fixture
async def session_service(db_session, redis_client):
    return SessionService(db_session, redis_client)

@pytest.mark.asyncio
async def test_user_authentication_and_token_flow(user_auth_service, token_service, session_service, db_session, redis_client):
    # Arrange: Register user
    username = "testuser"
    email = "test@example.com"
    password = "securepassword"
    user = await user_auth_service.register_user(username, email, password)

    # Act: Authenticate
    auth_user = await user_auth_service.authenticate_by_credentials(username, password)

    # Assert
    assert auth_user.id == user.id
    assert auth_user.username == username

    # Act: Create tokens
    jti = "test-jti"
    access_token = token_service.create_access_token(user)
    refresh_token = await token_service.create_refresh_token(user, jti)

    # Assert
    access_payload = jwt.decode(access_token, settings.JWT_PUBLIC_KEY, algorithms=["RS256"])
    assert access_payload["sub"] == str(user.id)
    refresh_payload = jwt.decode(refresh_token, settings.JWT_PUBLIC_KEY, algorithms=["RS256"])
    assert refresh_payload["jti"] == jti

    # Verify session
    session = await session_service.get_session(jti, user.id)
    assert session is not None
    assert session.refresh_token_hash == hashlib.sha256(refresh_token.encode()).hexdigest()

    # Act: Refresh tokens
    new_tokens = await token_service.refresh_tokens(refresh_token)

    # Assert
    assert "access_token" in new_tokens
    assert "refresh_token" in new_tokens
    assert await session_service.is_session_valid(jti, user.id) is False  # Old session revoked

    # Act: Revoke new session
    new_jti = jwt.decode(new_tokens["refresh_token"], settings.JWT_PUBLIC_KEY, algorithms=["RS256"])["jti"]
    await session_service.revoke_session(new_jti, user.id)

    # Assert
    assert await session_service.is_session_valid(new_jti, user.id) is False

@pytest.mark.asyncio
async def test_invalid_credentials(user_auth_service):
    # Act/Assert
    with pytest.raises(AuthenticationError, match="Invalid username or password"):
        await user_auth_service.authenticate_by_credentials("nonexistent", "wrongpassword")