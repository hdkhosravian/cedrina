import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession
from authlib.integrations.starlette_client import OAuth
from datetime import datetime, timezone, timedelta
from redis.asyncio import Redis

from src.domain.entities.user import User, Role
from src.domain.entities.oauth_profile import OAuthProfile, Provider
from src.domain.services.auth.oauth import OAuthService
from src.core.exceptions import AuthenticationError

@pytest_asyncio.fixture
async def db_session():
    session = AsyncMock(spec=AsyncSession)
    
    # This is the mock for the result of `await session.exec(...)`
    result_mock = MagicMock()
    
    # session.exec is an async function
    session.exec = AsyncMock(return_value=result_mock)
    
    return session

@pytest_asyncio.fixture
def oauth_service(db_session):
    with patch('src.domain.services.auth.oauth.Fernet') as mock_fernet:
        mock_fernet.return_value.encrypt.return_value = b"encrypted_token"
        with patch('src.core.config.settings.settings', autospec=True) as mock_settings:
            mock_settings.PGCRYPTO_KEY.get_secret_value.return_value = "test_key" * 8
            mock_settings.REDIS_URL = "redis://localhost:6379/0"
            service = OAuthService(db_session)
            yield service

@pytest.mark.asyncio
async def test_authenticate_with_oauth_success(oauth_service, db_session, mocker):
    # Arrange
    provider = "google"
    future_expires = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    token = {"access_token": "token", "expires_at": future_expires}
    user_info = {"sub": "123", "email": "test@example.com"}
    mocker.patch.object(oauth_service, "_fetch_user_info", return_value=user_info)
    user = User(id=1, username="testuser", email="test@example.com", is_active=True, roles=[Role.USER])
    db_session.exec.return_value.first = MagicMock(return_value=None)  # No existing profile
    db_session.exec.side_effect = [MagicMock(first=MagicMock(return_value=None)), MagicMock(first=MagicMock(return_value=user))]
    db_session.get.return_value = user

    # Act
    result_user, result_profile = await oauth_service.authenticate_with_oauth(provider, token)

    # Assert
    assert result_user == user
    assert isinstance(result_profile, OAuthProfile)
    assert result_profile.provider == Provider.GOOGLE
    assert result_profile.provider_user_id == "123"

@pytest.mark.asyncio
async def test_authenticate_with_oauth_existing_profile(oauth_service, db_session, mocker):
    # Arrange
    provider = "google"
    future_expires = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    token = {"access_token": "token", "expires_at": future_expires}
    user_info = {"sub": "123", "email": "test@example.com"}
    mocker.patch.object(oauth_service, "_fetch_user_info", return_value=user_info)
    user = User(id=1, username="testuser", email="test@example.com", is_active=True, roles=[Role.USER])
    oauth_profile = OAuthProfile(user_id=1, provider=Provider.GOOGLE, provider_user_id="123")
    db_session.exec.return_value.first = MagicMock(return_value=oauth_profile)
    db_session.get.return_value = user

    # Act
    result_user, result_profile = await oauth_service.authenticate_with_oauth(provider, token)

    # Assert
    assert result_user == user
    assert result_profile == oauth_profile

@pytest.mark.asyncio
async def test_authenticate_with_oauth_invalid_user_info(oauth_service, mocker):
    # Arrange
    provider = "google"
    future_expires = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    token = {"access_token": "token", "expires_at": future_expires}
    user_info = {"sub": "123"}  # Missing email
    mocker.patch.object(oauth_service, "_fetch_user_info", return_value=user_info)

    # Act/Assert
    with pytest.raises(AuthenticationError, match="OAuth authentication failed: Invalid OAuth user info"):
        await oauth_service.authenticate_with_oauth(provider, token)

@pytest.mark.asyncio
async def test_fetch_user_info_failure(oauth_service, mocker):
    # Arrange
    provider = "google"
    future_expires = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    token = {"access_token": "token", "expires_at": future_expires}

    mocker.patch.object(oauth_service, '_fetch_user_info', side_effect=AuthenticationError("Provider error"))

    # Act/Assert
    with pytest.raises(AuthenticationError, match="OAuth authentication failed: Provider error"):
        await oauth_service.authenticate_with_oauth(provider, token)

@pytest.mark.asyncio
async def test_authenticate_with_oauth_inactive_user(oauth_service, db_session, mocker):
    # Arrange
    provider = "google"
    future_expires = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    token = {"access_token": "token", "expires_at": future_expires}
    user_info = {"sub": "123", "email": "test@example.com"}
    mocker.patch.object(oauth_service, "_fetch_user_info", return_value=user_info)
    user = User(id=1, username="testuser", email="test@example.com", is_active=False, roles=[Role.USER])
    oauth_profile = OAuthProfile(user_id=1, provider=Provider.GOOGLE, provider_user_id="123")
    db_session.exec.return_value.first = MagicMock(return_value=oauth_profile)
    db_session.get.return_value = user

    # Act/Assert
    with pytest.raises(AuthenticationError, match="User account is inactive"):
        await oauth_service.authenticate_with_oauth(provider, token)

@pytest.mark.asyncio
async def test_authenticate_with_oauth_expired_token(oauth_service, db_session, mocker):
    # Arrange
    provider = "google"
    expired_token = {"access_token": "token", "expires_at": 0}  # Expired token
    user_info = {"sub": "123", "email": "test@example.com"}
    mocker.patch.object(oauth_service, "_fetch_user_info", return_value=user_info)

    # Act/Assert
    with pytest.raises(AuthenticationError, match="OAuth authentication failed: Token has expired"):
        await oauth_service.authenticate_with_oauth(provider, expired_token)

@pytest.mark.asyncio
async def test_validate_oauth_state_success(oauth_service):
    # Arrange
    state = "random-state-123"
    stored_state = "random-state-123"

    # Act
    result = await oauth_service.validate_oauth_state(state, stored_state)

    # Assert
    assert result is True

@pytest.mark.asyncio
async def test_validate_oauth_state_failure(oauth_service):
    # Arrange
    state = "random-state-123"
    stored_state = "different-state-456"

    # Act
    result = await oauth_service.validate_oauth_state(state, stored_state)

    # Assert
    assert result is False