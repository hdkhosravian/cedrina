"""Service for email confirmation tokens."""
import structlog
from src.domain.entities.user import User
from src.domain.interfaces.authentication.email_confirmation import IEmailConfirmationTokenService
from src.domain.value_objects.confirmation_token import ConfirmationToken

logger = structlog.get_logger(__name__)


class EmailConfirmationTokenService(IEmailConfirmationTokenService):
    async def generate_token(self, user: User) -> ConfirmationToken:
        token = ConfirmationToken.generate()
        user.email_confirmation_token = token.value
        logger.info("Generated email confirmation token", user_id=user.id)
        return token

    def validate_token(self, user: User, token: str) -> bool:
        return user.email_confirmation_token == token

    def invalidate_token(self, user: User) -> None:
        user.email_confirmation_token = None
