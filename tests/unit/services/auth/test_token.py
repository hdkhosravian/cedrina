import hashlib
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis
from jose import jwt, JWTError
from datetime import datetime, timezone, timedelta

from src.domain.entities.user import User, Role
from src.domain.entities.session import Session
from src.domain.services.auth.session import SessionService
from src.domain.services.auth.token import TokenService
from src.core.config.settings import settings
from src.core.exceptions import AuthenticationError

@pytest_asyncio.fixture
async def db_session():
    session = AsyncMock(spec=AsyncSession)
    session.exec = AsyncMock()
    return session

@pytest_asyncio.fixture
async def redis_client():
    client = AsyncMock(spec=Redis)
    client.setex = AsyncMock()
    return client

@pytest.fixture
def token_service(db_session, redis_client):
    session_service_mock = AsyncMock(spec=SessionService)
    return TokenService(db_session, redis_client, session_service=session_service_mock)

@pytest.mark.asyncio
async def test_create_access_token(token_service):
    # Arrange
    user = User(id=1, username="testuser", email="test@example.com", role=Role.USER, is_active=True)

    # Act
    token = await token_service.create_access_token(user)

    # Assert
    payload = jwt.decode(token, settings.JWT_PUBLIC_KEY, algorithms=["RS256"], audience=settings.JWT_AUDIENCE, issuer=settings.JWT_ISSUER)
    assert payload["sub"] == str(user.id)
    assert payload["username"] == user.username
    assert payload["email"] == user.email
    assert payload["role"] == user.role.value
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
    payload = jwt.decode(token, settings.JWT_PUBLIC_KEY, algorithms=["RS256"], audience=settings.JWT_AUDIENCE, issuer=settings.JWT_ISSUER)
    assert payload["sub"] == str(user.id)
    assert payload["jti"] == jti
    token_service.session_service.create_session.assert_called_once()

@pytest.mark.asyncio
async def test_refresh_tokens_success(token_service, db_session, redis_client, mocker):
    # Arrange
    user = User(id=1, username="testuser", email="test@example.com", role=Role.USER, is_active=True)
    jti = "test-jti"
    refresh_token = jwt.encode(
        {"sub": str(user.id), "jti": jti, "exp": datetime.now(timezone.utc) + timedelta(days=7), "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE},
        settings.JWT_PRIVATE_KEY.get_secret_value(),
        algorithm="RS256"
    )
    refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    session = Session(user_id=user.id, jti=jti, refresh_token_hash=refresh_token_hash)
    
    redis_client.get = AsyncMock(return_value=refresh_token_hash.encode())
    db_session.get.return_value = user
    mocker.patch("secrets.token_urlsafe", return_value="new-jti")
    
    # Mock SessionService methods
    token_service.session_service.get_session.return_value = session
    token_service.session_service.revoke_session.return_value = None
    
    # Act
    result = await token_service.refresh_tokens(refresh_token)

    # Assert
    assert "access_token" in result
    assert "refresh_token" in result
    assert result["token_type"] == "bearer"
    token_service.session_service.get_session.assert_called_once_with(jti, user.id)
    token_service.session_service.revoke_session.assert_called_once_with(jti, user.id)

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
    token = await token_service.create_access_token(user)
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
    token = await token_service.create_access_token(user)
    db_session.get.return_value = user

    # Act/Assert
    with pytest.raises(AuthenticationError, match="User is invalid or inactive"):
        await token_service.validate_token(token)

@pytest.mark.asyncio
async def test_validate_token_invalid_signature(token_service):
    # Arrange
    user = User(id=1, username="testuser", email="test@example.com", role=Role.USER, is_active=True)
    token = await token_service.create_access_token(user)
    # Tamper with the token
    invalid_token = token[:-4] + "fake"

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Invalid token"):
        await token_service.validate_token(invalid_token)

@pytest.mark.asyncio
async def test_validate_token_malformed(token_service):
    # Arrange
    invalid_token = "this.is.not.a.jwt"

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Invalid token"):
        await token_service.validate_token(invalid_token)

@pytest.mark.asyncio
async def test_validate_token_expired(token_service, db_session):
    # Arrange
    user = User(id=1, username="testuser", email="test@example.com", role=Role.USER, is_active=True)
    # Create a token with a past expiration time
    expired_payload = {
        "sub": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
        "iat": datetime.now(timezone.utc) - timedelta(minutes=10),
        "jti": "expired-jti"
    }
    expired_token = jwt.encode(expired_payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256")
    db_session.get.return_value = user

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Invalid token"):
        await token_service.validate_token(expired_token)

@pytest.mark.asyncio
async def test_validate_token_blacklisted(token_service, db_session, mocker):
    # Arrange
    user = User(id=1, username="testuser", email="test@example.com", role=Role.USER, is_active=True)
    token_payload = {
        "sub": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        "iat": datetime.now(timezone.utc),
        "jti": "blacklisted-jti"
    }
    token = jwt.encode(token_payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256")
    db_session.get.return_value = user
    mocker.patch.object(token_service, "_is_token_blacklisted", return_value=True)

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Token has been revoked or blacklisted"):
        await token_service.validate_token(token)