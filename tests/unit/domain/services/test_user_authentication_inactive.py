import pytest
from unittest.mock import AsyncMock, patch

from src.core.exceptions import AuthenticationError
from src.domain.entities.user import User
from src.domain.services.authentication.user_authentication_service import (
    UserAuthenticationService,
)
from src.domain.value_objects.password import Password
from src.domain.value_objects.username import Username


@pytest.mark.asyncio
async def test_login_requires_email_confirmation():
    repo = AsyncMock()
    event_publisher = AsyncMock()
    user = User(
        id=1,
        username="john",
        email="john@example.com",
        hashed_password="hash",
        is_active=False,
        email_confirmed=False,
    )
    repo.get_by_username.return_value = user

    service = UserAuthenticationService(repo, event_publisher)

    with patch.object(UserAuthenticationService, "verify_password", AsyncMock(return_value=True)):
        with patch("src.core.config.settings.settings.EMAIL_CONFIRMATION_ENABLED", True):
            with pytest.raises(AuthenticationError) as exc:
                await service.authenticate_user(Username("john"), Password("My$tr0ngPwd!"), language="en")

    assert "confirm" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_login_fails_when_unconfirmed_but_active():
    repo = AsyncMock()
    event_publisher = AsyncMock()
    user = User(
        id=2,
        username="mary",
        email="mary@example.com",
        hashed_password="hash",
        is_active=True,
        email_confirmed=False,
    )
    repo.get_by_username.return_value = user

    service = UserAuthenticationService(repo, event_publisher)

    with patch.object(UserAuthenticationService, "verify_password", AsyncMock(return_value=True)):
        with patch("src.core.config.settings.settings.EMAIL_CONFIRMATION_ENABLED", True):
            with pytest.raises(AuthenticationError) as exc:
                await service.authenticate_user(Username("mary"), Password("My$tr0ngPwd!"), language="en")

    assert "confirm" in str(exc.value).lower()
