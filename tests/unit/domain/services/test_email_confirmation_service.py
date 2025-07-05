import pytest
from unittest.mock import AsyncMock, Mock

from src.core.exceptions import UserNotFoundError
from src.domain.entities.user import User
from src.domain.services.email_confirmation.email_confirmation_service import (
    EmailConfirmationService,
)


@pytest.mark.asyncio
async def test_confirm_email_success():
    user = User(
        id=1,
        username="john",
        email="john@example.com",
        is_active=False,
        email_confirmation_token="abc",
        email_confirmed=False,
    )
    repo = AsyncMock()
    repo.get_by_confirmation_token.return_value = user
    repo.save.return_value = user
    token_service = AsyncMock()
    token_service.validate_token.return_value = True

    event_publisher = AsyncMock()
    service = EmailConfirmationService(repo, token_service, event_publisher)
    result = await service.confirm_email("abc", "en")

    assert result.is_active is True
    assert result.email_confirmed is True
    token_service.invalidate_token.assert_called_once_with(user)
    repo.save.assert_called_once_with(user)
    event_publisher.publish.assert_called_once()


@pytest.mark.asyncio
async def test_confirm_email_invalid_token():
    repo = AsyncMock()
    repo.get_by_confirmation_token.return_value = None
    token_service = AsyncMock()

    service = EmailConfirmationService(repo, token_service)
    with pytest.raises(UserNotFoundError):
        await service.confirm_email("wrong", "en")


@pytest.mark.asyncio
async def test_confirm_email_token_mismatch():
    """Confirm email fails when token does not match user record."""
    user = User(
        id=2,
        username="mary",
        email="mary@example.com",
        is_active=False,
        email_confirmation_token="correct",
        email_confirmed=False,
    )
    repo = AsyncMock()
    repo.get_by_confirmation_token.return_value = user
    token_service = Mock()
    token_service.validate_token.return_value = False

    service = EmailConfirmationService(repo, token_service)

    with pytest.raises(UserNotFoundError):
        await service.confirm_email("wrong", "en")
    token_service.invalidate_token.assert_not_called()
    repo.save.assert_not_called()
