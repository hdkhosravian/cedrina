import pytest
from unittest.mock import AsyncMock, patch

from src.domain.services.authentication.user_registration_service import (
    UserRegistrationService,
)
from src.domain.entities.user import User, Role
from src.domain.value_objects.email import Email
from src.domain.value_objects.password import Password
from src.domain.value_objects.username import Username
from src.domain.value_objects.confirmation_token import ConfirmationToken


@pytest.mark.asyncio
async def test_register_user_email_confirmation_flow():
    repo = AsyncMock()
    repo.get_by_username.return_value = None
    repo.get_by_email.return_value = None
    repo.save.side_effect = lambda u: u
    event_publisher = AsyncMock()
    token_service = AsyncMock()
    token_service.generate_token.return_value = ConfirmationToken("abc")
    email_service = AsyncMock()

    service = UserRegistrationService(repo, event_publisher, token_service, email_service)

    with patch("src.core.config.settings.settings.EMAIL_CONFIRMATION_ENABLED", True):
        user = await service.register_user(
            Username("john"),
            Email("john@example.com"),
            Password("My$tr0ngPwd!"),
            language="en",
        )

    assert user.is_active is False
    assert user.email_confirmed is False
    token_service.generate_token.assert_called_once_with(user)
    email_service.send_confirmation_email.assert_called_once_with(
        user, token_service.generate_token.return_value, "en"
    )


@pytest.mark.asyncio
async def test_register_user_without_email_confirmation():
    repo = AsyncMock()
    repo.get_by_username.return_value = None
    repo.get_by_email.return_value = None
    repo.save.side_effect = lambda u: u
    event_publisher = AsyncMock()
    token_service = AsyncMock()
    email_service = AsyncMock()

    service = UserRegistrationService(repo, event_publisher, token_service, email_service)

    with patch("src.core.config.settings.settings.EMAIL_CONFIRMATION_ENABLED", False):
        user = await service.register_user(
            Username("jane"),
            Email("jane@example.com"),
            Password("My$tr0ngPwd!"),
            language="en",
        )

    assert user.is_active is True
    assert user.email_confirmed is True
    token_service.generate_token.assert_not_called()
    email_service.send_confirmation_email.assert_not_called()
