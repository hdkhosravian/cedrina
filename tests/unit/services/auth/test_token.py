import hashlib
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis
from jose import jwt
from datetime import datetime, timezone, timedelta

from src.domain.entities.user import User, Role
from src.domain.entities.session import Session
from src.domain.services.auth.token import TokenService
from src.core.config import settings
from src.core.exceptions import AuthenticationError

@pytest_asyncio.fixture
async def db_session():
    return AsyncMock(spec=AsyncSession)

@pytest_asyncio.fixture
async def redis_client():
    return AsyncMock(spec=Redis)

@pytest_asyncio.fixture
def token_service(db_session, redis_client):
    return TokenService(db_session, redis_client)

@pytest.mark.asyncio
async def test_create_access_token(token_service):
    # Arrange
    user = User(id=1, username="testuser", email="test@example.com", role=Role.USER, is_active=True)

    # Act
    token = await token_service.create_access_token(user)

    # Assert
    payload = jwt.decode(token, settings.JWT_PUBLIC_KEY, algorithms=["RS256"])
    assert payload["sub"] == str(user.id)
    assert payload["username"] == user.username
    assert payload["email"] == user.email
    assert payload["role"] == user.role.value
    assert payload["iss"] == settings.JWT_ISSUER
    assert payload["aud"] == settings.JWT_AUDIENCE
    assert "jti" in payload

@pytest.mark.asyncio
async def test_create_refresh_token(token_service, db_session, redis_client, mocker):
    # Arrange
    user = User(id=1, username="testuser", email="test@example.com", role=Role.USER, is_active=True)
    jti = "test-jti"
    mocker.patch("secrets.token_urlsafe", return_value=jti)

    # Act
    token = await token_service.create_refresh_token(user, jti)

    # Assert
    payload = jwt.decode(token, settings.JWT_PUBLIC_KEY, algorithms=["RS256"])
    assert payload["sub"] == str(user.id)
    assert payload["jti"] == jti
    redis_client.setex.assert_called_once()
    db_session.add.assert_called_once()
    db_session.commit.assert_called_once()

@pytest.mark.asyncio
async def test_refresh_tokens_success(token_service, db_session, redis_client, mocker):
    # Arrange
    user = User(id=1, username="testuser", email="test@example.com", role=Role.USER, is_active=True)
    jti = "test-jti"
    refresh_token = jwt.encode(
        {"sub": str(user.id), "jti": jti, "exp": datetime.now(timezone.utc) + timedelta(days=7)},
        settings.JWT_PRIVATE_KEY,
        algorithm="RS256"
    )
    refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    session = Session(user_id=user.id, jti=jti, refresh_token_hash=refresh_token_hash)
    redis_client.get.return_value = refresh_token_hash.encode()
    db_session.exec.return_value.first.return_value = session
    db_session.get.return_value = user
    mocker.patch("secrets.token_urlsafe", return_value="new-jti")

    # Act
    result = await token_service.refresh_tokens(refresh_token)

    # Assert
    assert "access_token" in result
    assert "refresh_token" in result
    assert result["token_type"] == "bearer"
    redis_client.delete.assert_called_once_with(f"refresh_token:{jti}")
    db_session.add.assert_called()

@pytest.mark.asyncio
async def test_refresh_tokens_invalid_token(token_service, redis_client):
    # Arrange
    refresh_token = "invalid-token"

    # Act/Assert
    with pytest.raises(AuthenticationError, match="Invalid refresh token"):
        await token_service.refresh_tokens(refresh_token)

@pytest.mark.asyncio
async def test_validate_token_success(token_service, db_session):
    # Arrange
    user = User(id=1, username="testuser", email="test@example.com", role=Role.USER, is_active=True)
    token = jwt.encode(
        {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
            "iat": datetime.now(timezone.utc),
            "jti": "test-jti"
        },
        settings.JWT_PRIVATE_KEY,
        algorithm="RS256"
    )
    db_session.get.return_value = user

    # Act
    payload = await token_service.validate_token(token)

    # Assert
    assert payload["sub"] == str(user.id)
    db_session.get.assert_called_once_with(User, user.id)

@pytest.mark.asyncio
async def test_validate_token_inactive_user(token_service, db_session):
    # Arrange
    user = User(id=1, username="testuser", email="test@example.com", role=Role.USER, is_active=False)
    token = jwt.encode(
        {
            "sub": str(user.id),
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=15)
        },
        settings.JWT_PRIVATE_KEY,
        algorithm="RS256"
    )
    db_session.get.return_value = user

    # Act/Assert
    with pytest.raises(AuthenticationError, match="User is invalid or inactive"):
        await token_service.validate_token(token)