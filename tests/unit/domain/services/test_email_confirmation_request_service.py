import pytest
from unittest.mock import AsyncMock

from src.domain.entities.user import User
from src.domain.services.email_confirmation.email_confirmation_request_service import (
    EmailConfirmationRequestService,
)
from src.core.exceptions import EmailServiceError
from src.domain.value_objects.confirmation_token import ConfirmationToken


@pytest.fixture
def user():
    return User(id=1, username="john", email="john@example.com", is_active=False, email_confirmed=False)


@pytest.fixture
def service():
    repo = AsyncMock()
    token_service = AsyncMock()
    email_service = AsyncMock()
    return EmailConfirmationRequestService(repo, token_service, email_service)


@pytest.mark.asyncio
async def test_send_confirmation_email(service, user):
    token_obj = ConfirmationToken("abc")
    service._token_service.generate_token.return_value = token_obj
    service._user_repository.save.return_value = user
    service._email_service.send_confirmation_email.return_value = True

    result = await service.send_confirmation_email(user, "en")

    assert result is True
    service._token_service.generate_token.assert_called_once_with(user)
    service._user_repository.save.assert_called_once_with(user)
    service._email_service.send_confirmation_email.assert_called_once_with(user, token_obj, "en")


@pytest.mark.asyncio
async def test_resend_confirmation_email_inactive_user(service, user):
    service._user_repository.get_by_email.return_value = user
    service._token_service.generate_token.return_value = ConfirmationToken("abc")

    await service.resend_confirmation_email(user.email, "en")

    service._email_service.send_confirmation_email.assert_called_once()


@pytest.mark.asyncio
async def test_resend_confirmation_email_active_user_no_email(service, user):
    active_user = User(id=2, username="mary", email="mary@example.com", is_active=True, email_confirmed=True)
    service._user_repository.get_by_email.return_value = active_user

    await service.resend_confirmation_email(active_user.email, "en")

    service._email_service.send_confirmation_email.assert_not_called()

    service._user_repository.get_by_email.return_value = None
    await service.resend_confirmation_email("nobody@example.com", "en")
    service._email_service.send_confirmation_email.assert_not_called()


@pytest.mark.asyncio
async def test_send_confirmation_email_failure_logged(service, user):
    """Return False when the email service raises an error."""
    service._token_service.generate_token.return_value = ConfirmationToken("abc")
    service._user_repository.save.return_value = user
    service._email_service.send_confirmation_email.side_effect = EmailServiceError("smtp")

    result = await service.send_confirmation_email(user, "en")

    assert result is False
