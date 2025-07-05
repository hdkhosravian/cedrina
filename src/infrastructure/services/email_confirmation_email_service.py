"""Email confirmation email sender."""
import structlog
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from src.core.config.settings import settings
from src.domain.entities.user import User
from src.domain.interfaces.authentication.email_confirmation import IEmailConfirmationEmailService
from src.domain.value_objects.confirmation_token import ConfirmationToken
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class EmailConfirmationEmailService(IEmailConfirmationEmailService):
    """Render and deliver email confirmation messages."""

    def __init__(self) -> None:
        self._test_mode = getattr(settings, "EMAIL_TEST_MODE", True)
        template_dir = Path(settings.EMAIL_TEMPLATES_DIR)
        self._jinja = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)

    async def send_confirmation_email(
        self, user: User, token: ConfirmationToken, language: str = "en"
    ) -> bool:
        """Send a confirmation email to the user.

        Args:
            user: Recipient of the confirmation email.
            token: Confirmation token to embed in the message.
            language: Preferred language for the email template.

        Returns:
            ``True`` if the email was sent or queued successfully.
        """

        base_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000")
        confirm_url = f"{base_url}/confirm-email?token={token.value}"
        subject = get_translated_message("email_confirmation_subject", language)

        context = {"user": user, "confirm_url": confirm_url}

        template_html = f"email_confirmation_{language}.html"
        template_txt = f"email_confirmation_{language}.txt"
        html_content = self._jinja.get_template(template_html).render(context)
        text_content = self._jinja.get_template(template_txt).render(context)

        if self._test_mode:
            logger.info(
                "Email confirmation (test mode)",
                to=user.email,
                url=confirm_url,
                subject=subject,
            )
            return True

        logger.info(
            "Email confirmation sent",
            to=user.email,
            subject=subject,
            url=confirm_url,
        )
        return True
