import pytest
import pytest_asyncio
from unittest.mock import AsyncMock
from sqlalchemy.ext.asyncio import AsyncSession
from authlib.integrations.starlette_client import OAuth
from datetime import datetime, timezone

from src.domain.entities.user import User, Role
from src.domain.entities.oauth_profile import OAuthProfile, Provider
from src.domain.services.auth.oauth import OAuthService
from src.core.exceptions import AuthenticationError

@pytest_asyncio.fixture
async def db_session():
    return AsyncMock(spec=AsyncSession)

@pytest_asyncio.fixture
def oauth_service(db_session, mocker):
    service = OAuthService(db_session)
    mocker.patch.object(service.oauth, "create_client", return_value=AsyncMock())
    return service

@pytest.mark.asyncio
async def test_authenticate_with_oauth_existing_profile(oauth_service, db_session, mocker):
    # Arrange
    provider = "google"
    token = {"access_token": "token", "expires_at": 1699999999}
    user_info = {"sub": "123", "email": "test@example.com"}
    user = User(id=1, username="testuser", email="test@example.com", role=Role.USER, is_active=True)
    oauth_profile = OAuthProfile(
        user_id=1, provider=Provider.GOOGLE, provider_user_id="123", access_token=b"encrypted"
    )
    mocker.patch.object(oauth_service, "_fetch_user_info", return_value=user_info)
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
    token = {"access_token": "token", "expires_at": 1699999999}
    user_info = {"sub": "123", "email": "new@example.com"}
    mocker.patch.object(oauth_service, "_fetch_user_info", return_value=user_info)
    mocker.patch.object(oauth_service.fernet, "encrypt", return_value=b"encrypted")
    db_session.exec.return_value.first.side_effect = [None, None]  # No profile, no user
    db_session.add = AsyncMock()
    db_session.commit = AsyncMock()
    db_session.refresh = AsyncMock()

    # Act
    result_user, result_profile = await oauth_service.authenticate_with_oauth(provider, token)

    # Assert
    assert result_user.username.startswith("google_123")
    assert result_user.email == "new@example.com"
    assert result_profile.provider == Provider.GOOGLE
    assert result_profile.access_token == b"encrypted"
    db_session.add.assert_called()
    db_session.commit.assert_called()

@pytest.mark.asyncio
async def test_authenticate_with_oauth_invalid_user_info(oauth_service, mocker):
    # Arrange
    provider = "google"
    token = {"access_token": "token", "expires_at": 1699999999}
    user_info = {"sub": "123"}  # Missing email
    mocker.patch.object(oauth_service, "_fetch_user_info", return_value=user_info)

    # Act/Assert
    with pytest.raises(AuthenticationError, match="Invalid OAuth user info"):
        await oauth_service.authenticate_with_oauth(provider, token)

@pytest.mark.asyncio
async def test_fetch_user_info_failure(oauth_service, mocker):
    # Arrange
    provider = "google"
    token = {"access_token": "token"}
    mocker.patch.object(oauth_service.oauth, "create_client", return_value=AsyncMock())
    mocker.patch.object(oauth_service.oauth.create_client.return_value, "get", side_effect=Exception("Provider error"))

    # Act/Assert
    with pytest.raises(AuthenticationError, match="Failed to fetch user info"):
        await oauth_service._fetch_user_info(provider, token)