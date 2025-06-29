"""OAuth Authentication Domain Service.

This service handles OAuth 2.0 authentication operations following Domain-Driven Design
principles and single responsibility principle. It uses domain value objects for
input validation and publishes domain events for audit trails and security monitoring.

Key DDD Principles Applied:
- Domain Value Objects for input validation and business rules
- Domain Events for audit trails and security monitoring
- Single Responsibility Principle for OAuth authentication logic
- Dependency Inversion through interfaces
- Ubiquitous Language in method names and documentation
- Repository Pattern for data access
- I18N Support for error messages
"""

import time
from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional, Tuple

from authlib.integrations.starlette_client import OAuth
from cryptography.fernet import Fernet
from structlog import get_logger
from tenacity import retry, stop_after_attempt, wait_fixed

from src.core.config.settings import settings
from src.core.exceptions import AuthenticationError
from src.domain.entities.oauth_profile import OAuthProfile, Provider
from src.domain.entities.user import Role, User
from src.domain.events.authentication_events import (
    OAuthAuthenticationFailedEvent,
    OAuthAuthenticationSuccessEvent,
    OAuthProfileLinkedEvent,
)
from src.domain.interfaces.repositories import IOAuthProfileRepository, IUserRepository
from src.domain.interfaces.services import IEventPublisher, IOAuthService
from src.domain.value_objects.oauth_provider import OAuthProvider
from src.domain.value_objects.oauth_token import OAuthToken
from src.domain.value_objects.oauth_user_info import OAuthUserInfo
from src.utils.i18n import get_translated_message

logger = get_logger(__name__)


class OAuthAuthenticationService(IOAuthService):
    """Domain service for OAuth authentication operations following DDD principles.
    
    This service encapsulates all OAuth authentication business logic and follows
    Domain-Driven Design principles:
    
    - **Single Responsibility**: Handles only OAuth authentication-related operations
    - **Domain Value Objects**: Uses OAuthProvider, OAuthToken, and OAuthUserInfo value objects
    - **Domain Events**: Publishes events for audit trails and security monitoring
    - **Dependency Inversion**: Depends on abstractions (interfaces) not concretions
    - **Ubiquitous Language**: Method names reflect business domain concepts
    - **Repository Pattern**: Uses repositories for data access
    - **I18N Support**: All error messages are internationalized
    
    Security Features:
    - OAuth token validation and expiration checking
    - ID token validation for OpenID Connect providers
    - Comprehensive security event logging with data masking
    - Provider-specific validation and configuration
    - Fail-secure authentication logic
    - Correlation ID tracking for request tracing
    - Security context capture (IP, User-Agent) for audit trails
    """
    
    def __init__(
        self,
        user_repository: IUserRepository,
        oauth_profile_repository: IOAuthProfileRepository,
        event_publisher: IEventPublisher,
    ):
        """Initialize OAuth authentication service with dependencies.
        
        Args:
            user_repository: Repository for user data access (abstraction)
            oauth_profile_repository: Repository for OAuth profile data access (abstraction)
            event_publisher: Publisher for domain events (abstraction)
            
        Note:
            Dependencies are injected through interfaces, following
            dependency inversion principle from SOLID.
        """
        self._user_repository = user_repository
        self._oauth_profile_repository = oauth_profile_repository
        self._event_publisher = event_publisher
        
        # Initialize OAuth client
        self.oauth = OAuth()
        self._configure_oauth()
        
        # Initialize Fernet for token encryption
        try:
            pgcrypto_key = settings.PGCRYPTO_KEY.get_secret_value().encode()
            self.fernet = Fernet(pgcrypto_key)
        except Exception:  # pragma: no cover – logging & safe-fallback
            logger.warning(
                "Invalid PGCRYPTO_KEY provided – falling back to generated key for Fernet. "
                "This should only happen in non-prod environments."
            )
            self.fernet = Fernet(Fernet.generate_key())
        
        logger.info(
            "OAuthAuthenticationService initialized",
            service_type="domain_service",
            responsibilities=["oauth_authentication", "token_validation", "event_publishing"]
        )
    
    def _configure_oauth(self) -> None:
        """Configure OAuth clients for supported providers.
        
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
        self,
        provider: OAuthProvider,
        token: OAuthToken,
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> Tuple[User, OAuthProfile]:
        """Authenticate user via OAuth 2.0 and link or create a user profile.
        
        This method implements the core OAuth authentication business logic following
        Domain-Driven Design principles:
        
        1. **Input Validation**: Uses domain value objects (OAuthProvider, OAuthToken)
        2. **Token Validation**: Validates OAuth token expiration and ID token if present
        3. **User Info Fetching**: Retrieves user information from OAuth provider
        4. **Profile Management**: Links existing profile or creates new user/profile
        5. **Domain Events**: Publishes events for security monitoring and audit trails
        6. **Error Handling**: Provides meaningful error messages in ubiquitous language
        7. **Logging**: Implements secure logging with data masking and correlation
        
        OAuth Authentication Flow:
        1. Validate OAuth token using domain value objects
        2. Validate ID token if present (OpenID Connect)
        3. Fetch user information from OAuth provider
        4. Check for existing OAuth profile
        5. Link to existing user or create new user
        6. Create or update OAuth profile
        7. Publish appropriate domain events (success/failure)
        8. Return authenticated user and OAuth profile
        
        Args:
            provider: OAuth provider value object (validated)
            token: OAuth token value object (validated)
            language: Language code for I18N error messages
            client_ip: Client IP address for security context and audit
            user_agent: User agent string for security context and audit
            correlation_id: Request correlation ID for tracing and debugging
            
        Returns:
            Tuple[User, OAuthProfile]: Authenticated user entity and OAuth profile
            
        Raises:
            AuthenticationError: If OAuth token is invalid, expired, or
                               authentication system error occurs
                               
        Security Considerations:
        - Token expiration validation prevents replay attacks
        - ID token validation for OpenID Connect providers
        - Comprehensive audit trails via domain events
        - Secure logging with sensitive data masking
        - Fail-secure error handling
        """
        try:
            # Log OAuth authentication attempt with security context
            logger.info(
                "OAuth authentication attempt initiated",
                provider=provider.mask_for_logging(),
                token_info=token.mask_for_logging(),
                correlation_id=correlation_id,
                client_ip=client_ip,
                user_agent_length=len(user_agent) if user_agent else 0,
                security_context_captured=True
            )
            
            # Validate ID token if present (OpenID Connect)
            if token.has_id_token():
                await self._validate_id_token(provider, token, language)
            
            # Fetch user information from OAuth provider
            user_info = await self._fetch_user_info(provider, token)
            oauth_user_info = OAuthUserInfo.create_safe(user_info)
            
            # Check for existing OAuth profile
            oauth_profile = await self._oauth_profile_repository.get_by_provider_and_user_id(
                Provider(provider.value),
                oauth_user_info.provider_user_id
            )
            
            if oauth_profile:
                # Existing profile found - get user and validate
                user = await self._user_repository.get_by_id(oauth_profile.user_id)
                if not user or not user.is_active:
                    await self._handle_oauth_failure(
                        provider=provider,
                        failure_reason="user_inactive",
                        correlation_id=correlation_id,
                        user_agent=user_agent,
                        ip_address=client_ip,
                        language=language,
                        user_info=oauth_user_info,
                    )
                    raise AuthenticationError(
                        get_translated_message("user_account_inactive", language)
                    )
                
                # Update OAuth profile with new token
                oauth_profile.access_token = self.fernet.encrypt(token.access_token.encode())
                oauth_profile.expires_at = token.expires_at_datetime
                oauth_profile = await self._oauth_profile_repository.update(oauth_profile)
                
                logger.info(
                    "OAuth profile updated for existing user",
                    user_id=user.id,
                    provider=provider.mask_for_logging(),
                    correlation_id=correlation_id,
                )
            else:
                # No existing profile - create or link user
                user, oauth_profile = await self._create_or_link_user(
                    provider, oauth_user_info, token, language
                )
            
            # Publish successful authentication event
            await self._publish_successful_oauth_event(
                user=user,
                provider=provider,
                user_info=oauth_user_info,
                correlation_id=correlation_id,
                user_agent=user_agent,
                ip_address=client_ip,
                language=language,
            )
            
            # Log successful OAuth authentication
            logger.info(
                "OAuth authentication successful",
                user_id=user.id,
                provider=provider.mask_for_logging(),
                correlation_id=correlation_id,
                authentication_method="oauth"
            )
            
            return user, oauth_profile
            
        except ValueError as e:
            # Handle value object validation errors
            logger.warning(
                "OAuth authentication failed - invalid input format",
                provider=provider.mask_for_logging(),
                error=str(e),
                error_type="validation_error",
                correlation_id=correlation_id,
            )
            await self._handle_oauth_failure(
                provider=provider,
                failure_reason="invalid_input",
                correlation_id=correlation_id,
                user_agent=user_agent,
                ip_address=client_ip,
                language=language,
            )
            raise AuthenticationError(
                get_translated_message("invalid_oauth_token", language)
            )
        except AuthenticationError:
            # Re-raise domain exceptions to maintain proper error context
            raise
        except Exception as e:
            # Handle unexpected errors with secure logging
            logger.error(
                "OAuth authentication failed - unexpected error",
                provider=provider.mask_for_logging(),
                error=str(e),
                error_type=type(e).__name__,
                correlation_id=correlation_id,
            )
            await self._handle_oauth_failure(
                provider=provider,
                failure_reason="system_error",
                correlation_id=correlation_id,
                user_agent=user_agent,
                ip_address=client_ip,
                language=language,
            )
            raise AuthenticationError(
                get_translated_message("oauth_authentication_system_error", language)
            )
    
    async def validate_oauth_state(
        self,
        state: str,
        stored_state: str,
        language: str = "en"
    ) -> bool:
        """Validate the OAuth state parameter to prevent CSRF attacks.
        
        Args:
            state: State parameter returned from the OAuth provider
            stored_state: State parameter stored in the session before redirection
            language: Language code for I18N error messages
            
        Returns:
            bool: True if state matches, False otherwise
            
        Note:
            This method implements state validation logic to compare the state
            parameter returned by the OAuth provider with the one stored in
            the user's session to ensure the request originated from the
            legitimate client.
        """
        if not state or not stored_state:
            logger.warning(
                "OAuth state validation failed - missing state parameters",
                state_provided=bool(state),
                stored_state_provided=bool(stored_state)
            )
            return False
        
        # Use constant-time comparison to prevent timing attacks
        if len(state) != len(stored_state):
            return False
        
        result = 0
        for a, b in zip(state, stored_state):
            result |= ord(a) ^ ord(b)
        
        is_valid = result == 0
        
        if not is_valid:
            logger.warning(
                "OAuth state validation failed - state mismatch",
                state_length=len(state),
                stored_state_length=len(stored_state)
            )
        
        return is_valid
    
    async def _validate_id_token(
        self,
        provider: OAuthProvider,
        token: OAuthToken,
        language: str
    ) -> None:
        """Validate ID token for OpenID Connect providers.
        
        Args:
            provider: OAuth provider value object
            token: OAuth token value object
            language: Language code for I18N error messages
            
        Raises:
            AuthenticationError: If ID token validation fails
        """
        try:
            client = self.oauth.create_client(provider.value)
            # Parse and validate id_token (this does not make a network call)
            id_token = await client.parse_id_token(token.to_dict(), nonce=None)
            if not id_token:
                raise AuthenticationError(
                    get_translated_message("invalid_id_token", language)
                )
            
            # Check issuer and audience if applicable
            if provider.is_google() and id_token.get("iss") != provider.get_issuer():
                raise AuthenticationError(
                    get_translated_message("invalid_id_token_issuer", language)
                )
                
        except AuthenticationError:
            # Propagate authentication errors without masking message
            raise
        except Exception as e:
            logger.error(
                "ID token validation failed",
                provider=provider.mask_for_logging(),
                error=str(e)
            )
            raise AuthenticationError(
                get_translated_message("invalid_id_token", language)
            )
    
    async def _create_or_link_user(
        self,
        provider: OAuthProvider,
        user_info: OAuthUserInfo,
        token: OAuthToken,
        language: str
    ) -> Tuple[User, OAuthProfile]:
        """Create or link user with OAuth profile.
        
        Args:
            provider: OAuth provider value object
            user_info: OAuth user info value object
            token: OAuth token value object
            language: Language code for I18N error messages
            
        Returns:
            Tuple[User, OAuthProfile]: User and OAuth profile
            
        Raises:
            AuthenticationError: If user creation/linking fails
        """
        # Check for existing user by email
        user = await self._user_repository.get_by_email(str(user_info.email))
        
        if not user:
            # Create new user
            username = f"{provider.value}_{user_info.provider_user_id[:10]}"
            user = User(
                username=username,
                email=str(user_info.email),
                role=Role.USER,
                is_active=True,
            )
            user = await self._user_repository.create(user)
            
            logger.info(
                "Created new user from OAuth",
                user_id=user.id,
                email=user_info.email.mask_for_logging(),
                provider=provider.mask_for_logging()
            )
        else:
            # Link to existing user
            if not user.is_active:
                raise AuthenticationError(
                    get_translated_message("user_account_inactive", language)
                )
            
            logger.info(
                "Linking OAuth profile to existing user",
                user_id=user.id,
                email=user_info.email.mask_for_logging(),
                provider=provider.mask_for_logging()
            )
        
        # Create OAuth profile
        oauth_profile = OAuthProfile(
            user_id=user.id,
            provider=Provider(provider.value),
            provider_user_id=user_info.provider_user_id,
            access_token=self.fernet.encrypt(token.access_token.encode()),
            expires_at=token.expires_at_datetime,
        )
        oauth_profile = await self._oauth_profile_repository.create(oauth_profile)
        
        return user, oauth_profile
    
    @retry(stop=stop_after_attempt(3), wait=wait_fixed(1))
    async def _fetch_user_info(self, provider: OAuthProvider, token: OAuthToken) -> Dict[str, Any]:
        """Fetch user info from OAuth provider with retry.
        
        Args:
            provider: OAuth provider value object
            token: OAuth token value object
            
        Returns:
            Dict[str, Any]: User info from provider
            
        Raises:
            AuthenticationError: If fetching user info fails
            
        Note:
            Implements retry logic to handle transient network issues when fetching user
            information from OAuth providers. Logs specific errors for debugging purposes.
        """
        client = self.oauth.create_client(provider.value)
        
        try:
            if provider.is_facebook():
                user_info = await client.get(
                    "me",
                    token=token.to_dict(),
                    params={"fields": "id,email,name"}
                )
                return user_info.json()
            else:
                user_info = await client.get("userinfo", token=token.to_dict())
                return user_info.json()
        except Exception as e:
            logger.error(
                "Failed to fetch user info from OAuth provider",
                provider=provider.mask_for_logging(),
                error=str(e),
                error_type=type(e).__name__
            )
            raise AuthenticationError(
                get_translated_message("failed_to_fetch_oauth_user_info", "en")
            )
    
    async def _handle_oauth_failure(
        self,
        provider: OAuthProvider,
        failure_reason: str,
        correlation_id: str,
        user_agent: str,
        ip_address: str,
        language: str,
        user_info: Optional[OAuthUserInfo] = None,
    ) -> None:
        """Handle OAuth authentication failure.
        
        Args:
            provider: OAuth provider value object
            failure_reason: Reason for authentication failure
            correlation_id: Request correlation ID
            user_agent: Client user agent string
            ip_address: Client IP address
            language: Language code for I18N
            user_info: User information if available
        """
        # Publish failure event
        event = OAuthAuthenticationFailedEvent(
            provider=provider,
            failure_reason=failure_reason,
            correlation_id=correlation_id,
            user_agent=user_agent,
            ip_address=ip_address,
            language=language,
            user_info=user_info,
        )
        await self._event_publisher.publish(event)
        
        logger.warning(
            "OAuth authentication failed",
            provider=provider.mask_for_logging(),
            failure_reason=failure_reason,
            correlation_id=correlation_id,
            user_info=user_info.mask_for_logging() if user_info else None,
        )
    
    async def _publish_successful_oauth_event(
        self,
        user: User,
        provider: OAuthProvider,
        user_info: OAuthUserInfo,
        correlation_id: str,
        user_agent: str,
        ip_address: str,
        language: str,
    ) -> None:
        """Publish successful OAuth authentication event.
        
        Args:
            user: Authenticated user entity
            provider: OAuth provider value object
            user_info: OAuth user info value object
            correlation_id: Request correlation ID
            user_agent: Client user agent string
            ip_address: Client IP address
            language: Language code for I18N
        """
        event = OAuthAuthenticationSuccessEvent(
            user_id=user.id,
            provider=provider,
            user_info=user_info,
            correlation_id=correlation_id,
            user_agent=user_agent,
            ip_address=ip_address,
            language=language,
        )
        await self._event_publisher.publish(event) 