import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession
from authlib.integrations.starlette_client import OAuth
from datetime import datetime, timezone, timedelta
from redis.asyncio import Redis

from domain.entities.user import User, Role
from domain.entities.oauth_profile import OAuthProfile, Provider
from domain.services.auth.oauth import OAuthService
from core.exceptions import AuthenticationError

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
    with patch('domain.services.auth.oauth.Fernet') as mock_fernet:
        mock_fernet.return_value.encrypt.return_value = b"encrypted_token"
        with patch('core.config.settings.settings', autospec=True) as mock_settings:
            mock_settings.PGCRYPTO_KEY.get_secret_value.return_value = "test_key" * 8
            mock_settings.REDIS_URL = "redis://localhost:6379/0"
            service = OAuthService(db_session)
            yield service

@pytest.mark.asyncio
async def test_authenticate_with_oauth_existing_profile(oauth_service, db_session, mocker):
    # Arrange
    provider = "google"
    future_expires = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    token = {"access_token": "token", "expires_at": future_expires}
    user_info = {"sub": "123", "email": "test@example.com"}
    user = User(id=1, username="testuser", email="test@example.com", role=Role.USER, is_active=True)
    oauth_profile = OAuthProfile(
        user_id=1, provider=Provider.GOOGLE, provider_user_id="123", access_token=b"encrypted"
    )
    mocker.patch.object(oauth_service, "_fetch_user_info", return_value=user_info)

    # The result of `await db_session.exec(...)` has a `first()` method
    db_session.exec.return_value.first.return_value = oauth_profile
    db_session.get.return_value = user

    # Act
    result_user, result_profile = await oauth_service.authenticate_with_oauth(provider, token)

    # Assert
    assert result_user == user
    assert result_profile == oauth_profile
    oauth_service._fetch_user_info.assert_called_once_with(provider, token)
    db_session.exec.assert_called_once()

@pytest.mark.asyncio
async def test_authenticate_with_oauth_new_user(oauth_service, db_session, mocker):
    # Arrange
    provider = "google"
    future_expires = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    token = {"access_token": "test_token", "expires_at": future_expires}
    user_info = {"email": "new@example.com", "sub": "12345"}
    
    mocker.patch.object(oauth_service, '_fetch_user_info', return_value=user_info)
    db_session.exec.return_value.first.side_effect = [None, None]

    # Act
    user, oauth_profile = await oauth_service.authenticate_with_oauth(provider, token)

    # Assert
    assert user.email == user_info["email"]
    assert oauth_profile.provider_user_id == user_info["sub"]
    assert db_session.add.call_count == 2
    assert db_session.commit.call_count == 2

@pytest.mark.asyncio
async def test_authenticate_with_oauth_invalid_user_info(oauth_service, mocker):
    # Arrange
    provider = "google"
    future_expires = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    token = {"access_token": "token", "expires_at": future_expires}
    user_info = {"sub": "123"}  # Missing email
    mocker.patch.object(oauth_service, "_fetch_user_info", return_value=user_info)

    # Act/Assert
    with pytest.raises(AuthenticationError, match="Invalid OAuth user info"):
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
async def test_authenticate_with_oauth_existing_user_new_profile(oauth_service, db_session, mocker):
    # Arrange
    provider = "google"
    future_expires = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    token = {"access_token": "test_token", "expires_at": future_expires}
    user_info = {"email": "test@example.com", "sub": "12345"}
    existing_user = User(id=1, email="test@example.com", username="testuser", role=Role.USER, is_active=True)
    
    mocker.patch.object(oauth_service, '_fetch_user_info', return_value=user_info)
    # First exec call for OAuthProfile returns None, second for User returns existing_user
    db_session.exec.return_value.first.side_effect = [None, existing_user]

    # Act
    user, oauth_profile = await oauth_service.authenticate_with_oauth(provider, token)

    # Assert
    assert user.id == existing_user.id
    assert user.email == existing_user.email
    assert oauth_profile.user_id == existing_user.id
    assert oauth_profile.provider_user_id == user_info["sub"]
    assert db_session.add.call_count == 1
    assert db_session.commit.call_count == 1

@pytest.mark.asyncio
async def test_authenticate_with_oauth_expired_token(oauth_service, db_session, mocker):
    # Arrange
    provider = "google"
    expired_token = {"access_token": "token", "expires_at": 0}  # Expired token
    user_info = {"sub": "123", "email": "test@example.com"}
    mocker.patch.object(oauth_service, "_fetch_user_info", return_value=user_info)

    # Act/Assert
    with pytest.raises(AuthenticationError, match="Token has expired"):
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