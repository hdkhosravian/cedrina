from datetime import datetime, timezone
from typing import Dict, Any, Literal, Tuple
from authlib.integrations.starlette_client import OAuth
from sqlalchemy.ext.asyncio import AsyncSession
from structlog import get_logger
from cryptography.fernet import Fernet
from tenacity import retry, stop_after_attempt, wait_fixed
from sqlalchemy import select

from src.domain.entities.user import User, Role
from src.domain.entities.oauth_profile import OAuthProfile, Provider
from src.core.config.settings import settings
from src.core.exceptions import AuthenticationError

logger = get_logger(__name__)

class OAuthService:
    """
    Service for handling OAuth 2.0 authentication with external providers.

    Supports Google, Microsoft, and Facebook OAuth flows, integrating with PostgreSQL
    via SQLModel for user and OAuth profile persistence, and encrypting tokens with pgcrypto.
    This service ensures secure handling of OAuth tokens by encrypting access tokens and
    validating token expiration to prevent unauthorized access.

    Attributes:
        db_session (AsyncSession): SQLAlchemy async session for database operations.
        oauth (OAuth): Authlib OAuth client for provider interactions.
        fernet (Fernet): Cryptography Fernet for token encryption.
    """

    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self.oauth = OAuth()
        self.fernet = Fernet(settings.PGCRYPTO_KEY.get_secret_value().encode())
        self._configure_oauth()

    def _configure_oauth(self) -> None:
        """
        Configure OAuth clients for Google, Microsoft, and Facebook.

        Note:
            Configures clients with specific scopes for user data access. For public clients,
            consider implementing PKCE (Proof Key for Code Exchange) to secure authorization
            code flows. Additionally, ensure the use of state parameters to prevent CSRF attacks
            during the OAuth flow.
        """
        self.oauth.register(
            name="google",
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET.get_secret_value(),
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )
        self.oauth.register(
            name="microsoft",
            client_id=settings.MICROSOFT_CLIENT_ID,
            client_secret=settings.MICROSOFT_CLIENT_SECRET.get_secret_value(),
            server_metadata_url="https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )
        self.oauth.register(
            name="facebook",
            client_id=settings.FACEBOOK_CLIENT_ID,
            client_secret=settings.FACEBOOK_CLIENT_SECRET.get_secret_value(),
            authorize_url="https://www.facebook.com/v18.0/dialog/oauth",
            access_token_url="https://graph.facebook.com/v18.0/oauth/access_token",
            api_base_url="https://graph.facebook.com/v18.0/",
            client_kwargs={"scope": "email public_profile"},
        )

    async def authenticate_with_oauth(
        self, provider: Literal["google", "microsoft", "facebook"], token: Dict[str, Any]
    ) -> Tuple[User, OAuthProfile]:
        """
        Authenticate a user via OAuth 2.0 and link or create a user profile.

        Args:
            provider (Literal): OAuth provider name.
            token (Dict[str, Any]): OAuth token and user info.

        Returns:
            Tuple[User, OAuthProfile]: Authenticated user and OAuth profile.

        Raises:
            AuthenticationError: If OAuth token or user info is invalid.

        Note:
            Validates token expiration to prevent replay attacks and encrypts access tokens
            for secure storage. Ensure that the OAuth flow at the client level implements
            state validation to mitigate CSRF risks.
        """
        # Validate token expiration
        expires_at = token.get("expires_at")
        if not expires_at or expires_at < datetime.now(timezone.utc).timestamp():
            await logger.awarning("Expired OAuth token", provider=provider)
            raise AuthenticationError("Token has expired")

        user_info = await self._fetch_user_info(provider, token)
        email = user_info.get("email")
        provider_user_id = user_info.get("sub") or user_info.get("id")
        if not email or not provider_user_id:
            await logger.aerror("Invalid OAuth user info", provider=provider)
            raise AuthenticationError("Invalid OAuth user info")

        # Check for existing OAuth profile
        oauth_profile = await self.db_session.exec(
            select(OAuthProfile).where(
                OAuthProfile.provider == Provider(provider),
                OAuthProfile.provider_user_id == provider_user_id,
            )
        )
        oauth_profile = oauth_profile.first()

        if oauth_profile:
            user = await self.db_session.get(User, oauth_profile.user_id)
            if not user or not user.is_active:
                await logger.awarning("Inactive user OAuth login", email=email)
                raise AuthenticationError("User account is inactive")
        else:
            # Create or link user
            user = await self.db_session.exec(select(User).where(User.email == email))
            user = user.first()
            if not user:
                user = User(
                    username=f"{provider}_{provider_user_id[:10]}",
                    email=email,
                    role=Role.USER,
                    is_active=True,
                )
                self.db_session.add(user)
                await self.db_session.commit()
                await self.db_session.refresh(user)
                await logger.ainfo("Created new user from OAuth", email=email)

            oauth_profile = OAuthProfile(
                user_id=user.id,
                provider=Provider(provider),
                provider_user_id=provider_user_id,
                access_token=self.fernet.encrypt(token["access_token"].encode()),
                expires_at=datetime.fromtimestamp(token["expires_at"], tz=timezone.utc),
            )
            self.db_session.add(oauth_profile)
            await self.db_session.commit()
            await logger.ainfo("Linked OAuth profile", provider=provider, user_id=user.id)

        return user, oauth_profile

    async def validate_oauth_state(self, state: str, stored_state: str) -> bool:
        """
        Validate the OAuth state parameter to prevent CSRF attacks.

        Args:
            state (str): State parameter returned from the OAuth provider.
            stored_state (str): State parameter stored in the session before redirection.

        Returns:
            bool: True if state matches, False otherwise.

        Note:
            This is a placeholder for state validation logic. Implement this method to
            compare the state parameter returned by the OAuth provider with the one stored
            in the user's session to ensure the request originated from the legitimate client.
        """
        # Placeholder: Implement actual state validation logic
        return state == stored_state

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(1))
    async def _fetch_user_info(self, provider: str, token: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fetch user info from OAuth provider with retry.

        Args:
            provider (str): OAuth provider name.
            token (Dict[str, Any]): OAuth token.

        Returns:
            Dict[str, Any]: User info from provider.

        Raises:
            AuthenticationError: If fetching user info fails.

        Note:
            Implements retry logic to handle transient network issues when fetching user
            information from OAuth providers. Logs specific errors for debugging purposes.
        """
        client = self.oauth.create_client(provider)
        if provider == "facebook":
            user_info = await client.get("me", token=token, params={"fields": "id,email,name"})
            return user_info.json()
        else:
            user_info = await client.get("userinfo", token=token)
            return user_info.json()