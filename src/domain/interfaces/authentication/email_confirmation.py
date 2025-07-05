"""Email confirmation service interfaces."""
from abc import ABC, abstractmethod

from src.domain.entities.user import User
from src.domain.value_objects.confirmation_token import ConfirmationToken


class IEmailConfirmationTokenService(ABC):
    @abstractmethod
    async def generate_token(self, user: User) -> ConfirmationToken:
        """Generate a confirmation token and assign to user."""
        raise NotImplementedError

    @abstractmethod
    def validate_token(self, user: User, token: str) -> bool:
        """Validate provided confirmation token."""
        raise NotImplementedError

    @abstractmethod
    def invalidate_token(self, user: User) -> None:
        """Invalidate confirmation token."""
        raise NotImplementedError


class IEmailConfirmationEmailService(ABC):
    @abstractmethod
    async def send_confirmation_email(
        self, user: User, token: ConfirmationToken, language: str = "en"
    ) -> bool:
        """Send email confirmation message."""
        raise NotImplementedError
