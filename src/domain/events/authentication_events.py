"""Authentication Domain Events.

These events represent significant business occurrences in the authentication domain
that other parts of the system may need to react to (logging, monitoring, notifications).
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from .password_reset_events import BaseDomainEvent
from src.domain.value_objects.oauth_provider import OAuthProvider
from src.domain.value_objects.oauth_token import OAuthToken
from src.domain.value_objects.oauth_user_info import OAuthUserInfo


@dataclass(frozen=True)
class UserRegisteredEvent(BaseDomainEvent):
    """Event published when a user successfully registers.
    
    This event signals that a new user account has been created
    and can trigger welcome emails, analytics, and audit logging.
    
    Attributes:
        username: Username of the registered user
        email: Email address of the registered user
        role: Role assigned to the user
        registration_source: Source of registration (web, api, etc.)
        user_agent: Browser/client user agent
        ip_address: Client IP address
    """
    
    username: str
    email: str
    role: str
    registration_source: str = "web"
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    
    @classmethod
    def create(
        cls,
        user_id: int,
        username: str,
        email: str,
        role: str,
        registration_source: str = "web",
        correlation_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> 'UserRegisteredEvent':
        """Create user registration event with current timestamp.
        
        Args:
            user_id: ID of the registered user
            username: Username of the registered user
            email: Email address of the registered user
            role: Role assigned to the user
            registration_source: Source of registration
            correlation_id: Optional correlation ID for tracking
            user_agent: Browser/client user agent
            ip_address: Client IP address
            
        Returns:
            UserRegisteredEvent: New event instance
        """
        return cls(
            occurred_at=datetime.now(timezone.utc),
            user_id=user_id,
            correlation_id=correlation_id,
            username=username,
            email=email,
            role=role,
            registration_source=registration_source,
            user_agent=user_agent,
            ip_address=ip_address,
        )


@dataclass(frozen=True)
class UserLoggedInEvent(BaseDomainEvent):
    """Event published when a user successfully logs in.
    
    This event signals successful authentication and can trigger
    security monitoring, analytics, and personalization features.
    
    Attributes:
        username: Username of the authenticated user
        login_method: Method used for login (password, oauth, etc.)
        session_id: Session identifier for the login
        user_agent: Browser/client user agent
        ip_address: Client IP address
        previous_login_at: Timestamp of previous login (if available)
    """
    
    username: str
    login_method: str = "password"
    session_id: Optional[str] = None
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    previous_login_at: Optional[datetime] = None
    
    @classmethod
    def create(
        cls,
        user_id: int,
        username: str,
        login_method: str = "password",
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        previous_login_at: Optional[datetime] = None,
    ) -> 'UserLoggedInEvent':
        """Create user login event with current timestamp.
        
        Args:
            user_id: ID of the authenticated user
            username: Username of the authenticated user
            login_method: Method used for login
            session_id: Session identifier
            correlation_id: Optional correlation ID for tracking
            user_agent: Browser/client user agent
            ip_address: Client IP address
            previous_login_at: Timestamp of previous login
            
        Returns:
            UserLoggedInEvent: New event instance
        """
        return cls(
            occurred_at=datetime.now(timezone.utc),
            user_id=user_id,
            correlation_id=correlation_id,
            username=username,
            login_method=login_method,
            session_id=session_id,
            user_agent=user_agent,
            ip_address=ip_address,
            previous_login_at=previous_login_at,
        )


@dataclass(frozen=True)
class UserLoggedOutEvent(BaseDomainEvent):
    """Event published when a user logs out.
    
    This event signals session termination and can trigger
    security monitoring and session cleanup operations.
    
    Attributes:
        username: Username of the user who logged out
        session_id: Session identifier that was terminated
        logout_reason: Reason for logout (user_initiated, expired, revoked)
        user_agent: Browser/client user agent
        ip_address: Client IP address
        session_duration: Duration of the session in seconds
    """
    
    username: str
    session_id: Optional[str] = None
    logout_reason: str = "user_initiated"
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    session_duration: Optional[int] = None
    
    @classmethod
    def create(
        cls,
        user_id: int,
        username: str,
        session_id: Optional[str] = None,
        logout_reason: str = "user_initiated",
        correlation_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        session_duration: Optional[int] = None,
    ) -> 'UserLoggedOutEvent':
        """Create user logout event with current timestamp.
        
        Args:
            user_id: ID of the user who logged out
            username: Username of the user
            session_id: Session identifier that was terminated
            logout_reason: Reason for logout
            correlation_id: Optional correlation ID for tracking
            user_agent: Browser/client user agent
            ip_address: Client IP address
            session_duration: Duration of the session in seconds
            
        Returns:
            UserLoggedOutEvent: New event instance
        """
        return cls(
            occurred_at=datetime.now(timezone.utc),
            user_id=user_id,
            correlation_id=correlation_id,
            username=username,
            session_id=session_id,
            logout_reason=logout_reason,
            user_agent=user_agent,
            ip_address=ip_address,
            session_duration=session_duration,
        )


@dataclass(frozen=True)
class TokenRefreshedEvent(BaseDomainEvent):
    """Event published when JWT tokens are refreshed.
    
    This event signals token rotation and can trigger security
    monitoring and analytics.
    
    Attributes:
        username: Username of the user refreshing tokens
        old_token_id: ID of the old refresh token
        new_token_id: ID of the new refresh token
        token_type: Type of token refreshed (refresh, access)
        user_agent: Browser/client user agent
        ip_address: Client IP address
    """
    
    username: str
    old_token_id: str
    new_token_id: str
    token_type: str = "refresh"
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    
    @classmethod
    def create(
        cls,
        user_id: int,
        username: str,
        old_token_id: str,
        new_token_id: str,
        token_type: str = "refresh",
        correlation_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> 'TokenRefreshedEvent':
        """Create token refresh event with current timestamp.
        
        Args:
            user_id: ID of the user refreshing tokens
            username: Username of the user
            old_token_id: ID of the old refresh token
            new_token_id: ID of the new refresh token
            token_type: Type of token refreshed
            correlation_id: Optional correlation ID for tracking
            user_agent: Browser/client user agent
            ip_address: Client IP address
            
        Returns:
            TokenRefreshedEvent: New event instance
        """
        return cls(
            occurred_at=datetime.now(timezone.utc),
            user_id=user_id,
            correlation_id=correlation_id,
            username=username,
            old_token_id=old_token_id,
            new_token_id=new_token_id,
            token_type=token_type,
            user_agent=user_agent,
            ip_address=ip_address,
        )


@dataclass(frozen=True)
class AuthenticationFailedEvent(BaseDomainEvent):
    """Event published when authentication fails.
    
    This event signals failed authentication attempts and can trigger
    security monitoring, rate limiting, and threat detection.
    
    Attributes:
        attempted_username: Username that was attempted
        failure_reason: Reason for authentication failure
        attempt_source: Source of the attempt (login, api, etc.)
        user_agent: Browser/client user agent
        ip_address: Client IP address
        attempts_count: Number of consecutive failed attempts
    """
    
    attempted_username: str
    failure_reason: str
    attempt_source: str = "login"
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    attempts_count: int = 1
    
    @classmethod
    def create(
        cls,
        attempted_username: str,
        failure_reason: str,
        attempt_source: str = "login",
        correlation_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        attempts_count: int = 1,
    ) -> 'AuthenticationFailedEvent':
        """Create authentication failure event with current timestamp.
        
        Args:
            attempted_username: Username that was attempted
            failure_reason: Reason for authentication failure
            attempt_source: Source of the attempt
            correlation_id: Optional correlation ID for tracking
            user_agent: Browser/client user agent
            ip_address: Client IP address
            attempts_count: Number of consecutive failed attempts
            
        Returns:
            AuthenticationFailedEvent: New event instance
        """
        return cls(
            occurred_at=datetime.now(timezone.utc),
            user_id=0,  # No valid user ID for failed attempts
            correlation_id=correlation_id,
            attempted_username=attempted_username,
            failure_reason=failure_reason,
            attempt_source=attempt_source,
            user_agent=user_agent,
            ip_address=ip_address,
            attempts_count=attempts_count,
        )


@dataclass(frozen=True)
class PasswordChangedEvent(BaseDomainEvent):
    """Event published when a user changes their password.
    
    This event signals password updates and can trigger security
    notifications and audit logging.
    
    Attributes:
        username: Username of the user who changed password
        change_method: Method used to change password (self_service, admin, reset)
        user_agent: Browser/client user agent
        ip_address: Client IP address
        forced_change: Whether password change was forced
    """
    
    username: str
    change_method: str = "self_service"
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    forced_change: bool = False
    
    @classmethod
    def create(
        cls,
        user_id: int,
        username: str,
        change_method: str = "self_service",
        correlation_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        forced_change: bool = False,
    ) -> 'PasswordChangedEvent':
        """Create password change event with current timestamp.
        
        Args:
            user_id: ID of the user who changed password
            username: Username of the user
            change_method: Method used to change password
            correlation_id: Optional correlation ID for tracking
            user_agent: Browser/client user agent
            ip_address: Client IP address
            forced_change: Whether password change was forced
            
        Returns:
            PasswordChangedEvent: New event instance
        """
        return cls(
            occurred_at=datetime.now(timezone.utc),
            user_id=user_id,
            correlation_id=correlation_id,
            username=username,
            change_method=change_method,
            user_agent=user_agent,
            ip_address=ip_address,
            forced_change=forced_change,
        )


@dataclass(frozen=True)
class EmailConfirmedEvent(BaseDomainEvent):
    """Event published when a user confirms their email."""

    username: str

    @classmethod
    def create(
        cls,
        user_id: int,
        username: str,
        correlation_id: Optional[str] = None,
    ) -> "EmailConfirmedEvent":
        return cls(
            occurred_at=datetime.now(timezone.utc),
            user_id=user_id,
            correlation_id=correlation_id,
            username=username,
        )


class OAuthAuthenticationSuccessEvent(BaseDomainEvent):
    """Domain event for successful OAuth authentication.
    
    This event is published when a user successfully authenticates
    via OAuth, providing audit trails and security monitoring.
    """
    
    def __init__(
        self,
        user_id: int,
        provider: OAuthProvider,
        user_info: OAuthUserInfo,
        correlation_id: str,
        user_agent: str,
        ip_address: str,
        language: str = "en",
    ):
        """Initialize OAuth authentication success event.
        
        Args:
            user_id: ID of the authenticated user
            provider: OAuth provider used for authentication
            user_info: User information from OAuth provider
            correlation_id: Request correlation ID for tracing
            user_agent: Client user agent string
            ip_address: Client IP address
            language: Language code for I18N
        """
        super().__init__(
            event_type="oauth_authentication_success",
            correlation_id=correlation_id,
            user_agent=user_agent,
            ip_address=ip_address,
            language=language,
        )
        self.user_id = user_id
        self.provider = provider
        self.user_info = user_info
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization.
        
        Returns:
            Dict[str, Any]: Event data dictionary
        """
        base_data = super().to_dict()
        base_data.update({
            "user_id": self.user_id,
            "provider": str(self.provider),
            "user_info": self.user_info.mask_for_logging(),
        })
        return base_data


class OAuthAuthenticationFailedEvent(BaseDomainEvent):
    """Domain event for failed OAuth authentication.
    
    This event is published when OAuth authentication fails,
    providing audit trails and security monitoring.
    """
    
    def __init__(
        self,
        provider: OAuthProvider,
        failure_reason: str,
        correlation_id: str,
        user_agent: str,
        ip_address: str,
        language: str = "en",
        user_info: Optional[OAuthUserInfo] = None,
    ):
        """Initialize OAuth authentication failure event.
        
        Args:
            provider: OAuth provider used for authentication
            failure_reason: Reason for authentication failure
            correlation_id: Request correlation ID for tracing
            user_agent: Client user agent string
            ip_address: Client IP address
            language: Language code for I18N
            user_info: User information if available
        """
        super().__init__(
            event_type="oauth_authentication_failed",
            correlation_id=correlation_id,
            user_agent=user_agent,
            ip_address=ip_address,
            language=language,
        )
        self.provider = provider
        self.failure_reason = failure_reason
        self.user_info = user_info
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization.
        
        Returns:
            Dict[str, Any]: Event data dictionary
        """
        base_data = super().to_dict()
        base_data.update({
            "provider": str(self.provider),
            "failure_reason": self.failure_reason,
            "user_info": self.user_info.mask_for_logging() if self.user_info else None,
        })
        return base_data


class OAuthProfileLinkedEvent(BaseDomainEvent):
    """Domain event for OAuth profile linking.
    
    This event is published when an OAuth profile is linked
    to an existing user account.
    """
    
    def __init__(
        self,
        user_id: int,
        provider: OAuthProvider,
        user_info: OAuthUserInfo,
        correlation_id: str,
        user_agent: str,
        ip_address: str,
        language: str = "en",
    ):
        """Initialize OAuth profile linked event.
        
        Args:
            user_id: ID of the user whose profile was linked
            provider: OAuth provider used for linking
            user_info: User information from OAuth provider
            correlation_id: Request correlation ID for tracing
            user_agent: Client user agent string
            ip_address: Client IP address
            language: Language code for I18N
        """
        super().__init__(
            event_type="oauth_profile_linked",
            correlation_id=correlation_id,
            user_agent=user_agent,
            ip_address=ip_address,
            language=language,
        )
        self.user_id = user_id
        self.provider = provider
        self.user_info = user_info
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization.
        
        Returns:
            Dict[str, Any]: Event data dictionary
        """
        base_data = super().to_dict()
        base_data.update({
            "user_id": self.user_id,
            "provider": str(self.provider),
            "user_info": self.user_info.mask_for_logging(),
        })
        return base_data 