"""Domain service for confirming user email addresses."""

from typing import Optional
import structlog

from src.core.exceptions import UserNotFoundError
from src.domain.entities.user import User
from src.domain.interfaces import (
    IEmailConfirmationTokenService,
    IUserRepository,
    IEventPublisher,
)
from src.domain.events.authentication_events import EmailConfirmedEvent
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class EmailConfirmationService:
    """Handle email confirmation logic for newly registered users."""
    def __init__(
        self,
        user_repository: IUserRepository,
        token_service: IEmailConfirmationTokenService,
        event_publisher: IEventPublisher | None = None,
    ) -> None:
        self._user_repository = user_repository
        self._token_service = token_service
        self._event_publisher = event_publisher

    async def confirm_email(self, token: str, language: str = "en") -> User:
        """Confirm a user's email using the provided token.

        Args:
            token: Confirmation token received from the user.
            language: Language code used for translated messages.

        Returns:
            The updated ``User`` entity with ``is_active`` and ``email_confirmed``
            set to ``True``.

        Raises:
            UserNotFoundError: If no matching user is found or the token is
                invalid.
        """

        user = await self._user_repository.get_by_confirmation_token(token)
        if not user:
            raise UserNotFoundError(get_translated_message("invalid_token", language))

        if self._token_service.validate_token(user, token):
            user.is_active = True
            user.email_confirmed = True
            self._token_service.invalidate_token(user)
            await self._user_repository.save(user)
            if self._event_publisher:
                event = EmailConfirmedEvent.create(
                    user_id=user.id,
                    username=user.username,
                )
                await self._event_publisher.publish(event)
            return user

        raise UserNotFoundError(get_translated_message("invalid_token", language))
