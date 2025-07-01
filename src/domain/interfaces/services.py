"""Service interfaces for domain services.

These interfaces define contracts for domain services,
enabling dependency inversion and better testability.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional, Tuple

from pydantic import EmailStr

from src.domain.entities.user import User
from src.domain.events.password_reset_events import BaseDomainEvent
from src.domain.value_objects.reset_token import ResetToken
from src.domain.value_objects.username import Username
from src.domain.value_objects.password import Password
from src.domain.value_objects.oauth_provider import OAuthProvider
from src.domain.value_objects.oauth_token import OAuthToken
from src.domain.value_objects.oauth_user_info import OAuthUserInfo
from src.domain.value_objects.jwt_token import AccessToken, RefreshToken


class IRateLimitingService(ABC):
    """Interface for rate limiting service."""
    
    @abstractmethod
    async def is_user_rate_limited(self, user_id: int) -> bool:
        """Check if user is currently rate limited.
        
        Args:
            user_id: User ID to check
            
        Returns:
            bool: True if user is rate limited
        """
        pass
    
    @abstractmethod
    async def record_attempt(self, user_id: int) -> None:
        """Record a rate limiting attempt for user.
        
        Args:
            user_id: User ID making the attempt
        """
        pass
    
    @abstractmethod
    async def get_time_until_reset(self, user_id: int) -> Optional[datetime]:
        """Get time when rate limit resets for user.
        
        Args:
            user_id: User ID to check
            
        Returns:
            Optional[datetime]: Reset time if limited, None otherwise
        """
        pass


class IPasswordResetTokenService(ABC):
    """Interface for password reset token service."""
    
    @abstractmethod
    async def generate_token(self, user: User) -> ResetToken:
        """Generate a secure password reset token with rate limiting.
        
        Args:
            user: User to generate token for
            
        Returns:
            ResetToken: Generated token with expiration
            
        Raises:
            RateLimitExceededError: If rate limit is exceeded for this user
        """
        pass
    
    @abstractmethod
    def validate_token(self, user: User, token: str) -> bool:
        """Validate a password reset token.
        
        Args:
            user: User entity with stored token
            token: Token to validate
            
        Returns:
            bool: True if token is valid
        """
        pass
    
    @abstractmethod
    def invalidate_token(self, user: User, reason: str = "used") -> None:
        """Invalidate a password reset token.
        
        Args:
            user: User entity to invalidate token for
            reason: Reason for invalidation
        """
        pass
    
    @abstractmethod
    def is_token_expired(self, user: User) -> bool:
        """Check if user's token is expired.
        
        Args:
            user: User entity to check
            
        Returns:
            bool: True if token is expired
        """
        pass


class IPasswordResetEmailService(ABC):
    """Interface for password reset email service."""
    
    @abstractmethod
    async def send_password_reset_email(
        self,
        user: User,
        token: ResetToken,
        language: str = "en"
    ) -> bool:
        """Send password reset email to user.
        
        Args:
            user: User to send email to
            token: Reset token to include in email
            language: Language for email content
            
        Returns:
            bool: True if email sent successfully
        """
        pass


class IEventPublisher(ABC):
    """Interface for domain event publishing."""
    
    @abstractmethod
    async def publish(self, event: BaseDomainEvent) -> None:
        """Publish a domain event.
        
        Args:
            event: Domain event to publish
        """
        pass
    
    @abstractmethod
    async def publish_many(self, events: List[BaseDomainEvent]) -> None:
        """Publish multiple domain events.
        
        Args:
            events: List of domain events to publish
        """
        pass


class IUserAuthenticationService(ABC):
    """Interface for user authentication service following DDD principles.
    
    This service handles user authentication using domain value objects
    and publishes domain events for audit trails and security monitoring.
    """
    
    @abstractmethod
    async def authenticate_user(
        self,
        username: Username,
        password: Password,
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> User:
        """Authenticate user with domain value objects and security context.
        
        This method follows DDD principles by:
        - Using domain value objects for input validation
        - Accepting security context for audit trails
        - Publishing domain events for security monitoring
        - Following single responsibility principle
        - Supporting I18N for error messages
        
        Args:
            username: Username value object (validated and normalized)
            password: Password value object (validated)
            language: Language code for I18N error messages
            client_ip: Client IP address for security context
            user_agent: User agent string for security context
            correlation_id: Request correlation ID for tracing
            
        Returns:
            User: Authenticated user entity
            
        Raises:
            AuthenticationError: If credentials are invalid or user inactive
        """
        pass
    
    @abstractmethod
    async def verify_password(self, user: User, password: Password) -> bool:
        """Verify password for user using domain value objects.
        
        Args:
            user: User entity with hashed password
            password: Password value object to verify
            
        Returns:
            bool: True if password is correct
        """
        pass


class IUserRegistrationService(ABC):
    """Interface for user registration service."""
    
    @abstractmethod
    async def register_user(
        self,
        username: 'Username',
        email: 'Email',
        password: 'Password',
        language: str = "en",
        correlation_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        role: 'Role' = None,
    ) -> 'User':
        """Register a new user.
        
        Args:
            username: Username value object
            email: Email value object
            password: Password value object
            language: Language code for I18N
            correlation_id: Optional correlation ID for tracking
            user_agent: Browser/client user agent
            ip_address: Client IP address
            role: User role (defaults to USER)
        Returns:
            User: Newly created user entity
        Raises:
            DuplicateUserError: If username or email already exists
        """
        pass
    
    @abstractmethod
    async def check_username_availability(self, username: str) -> bool:
        """Check if username is available for registration.
        
        Args:
            username: Username to check
            
        Returns:
            bool: True if username is available
        """
        pass
    
    @abstractmethod
    async def check_email_availability(self, email: str) -> bool:
        """Check if email is available for registration.
        
        Args:
            email: Email to check
            
        Returns:
            bool: True if email is available
        """
        pass


class IPasswordChangeService(ABC):
    """Interface for password change service following DDD principles."""
    
    @abstractmethod
    async def change_password(
        self,
        user_id: int,
        old_password: str,
        new_password: str,
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> None:
        """Change user password with comprehensive security validation.
        
        Args:
            user_id: ID of the user changing password
            old_password: Current password for verification
            new_password: New password to set
            language: Language code for error messages
            client_ip: Client IP address for audit
            user_agent: User agent string for audit
            correlation_id: Correlation ID for request tracking
            
        Raises:
            ValueError: If input parameters are invalid
            AuthenticationError: If user not found or inactive
            InvalidOldPasswordError: If old password is incorrect
            PasswordReuseError: If new password same as old password
            PasswordPolicyError: If new password doesn't meet policy
        """
        pass


class ITokenService(ABC):
    """Interface for JWT token service."""
    
    @abstractmethod
    async def create_access_token(self, user: User) -> str:
        """Create access token for user.
        
        Args:
            user: User entity
            
        Returns:
            str: JWT access token
        """
        pass
    
    @abstractmethod
    async def create_refresh_token(self, user: User) -> str:
        """Create refresh token for user.
        
        Args:
            user: User entity
            
        Returns:
            str: JWT refresh token
        """
        pass
    
    @abstractmethod
    async def refresh_tokens(self, refresh_token: str) -> dict:
        """Refresh access token using refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            dict: New token pair
            
        Raises:
            AuthenticationError: If refresh token is invalid
        """
        pass
    
    @abstractmethod
    async def validate_access_token(self, token: str) -> dict:
        """Validate access token.
        
        Args:
            token: JWT access token
            
        Returns:
            dict: Token payload if valid
            
        Raises:
            AuthenticationError: If token is invalid
        """
        pass
    
    @abstractmethod
    async def revoke_refresh_token(self, token: str, language: str = "en") -> None:
        """Revoke refresh token.
        
        Args:
            token: Refresh token to revoke
            language: Language code for error messages
        """
        pass

    @abstractmethod
    async def revoke_access_token(self, jti: str, expires_in: int | None = None) -> None:
        """Revoke access token by blacklisting it.
        
        Args:
            jti: JWT ID to blacklist
            expires_in: Optional expiration time for blacklist entry
        """
        pass

    @abstractmethod
    async def validate_token(self, token: str, language: str = "en") -> dict:
        """Validate JWT token.
        
        Args:
            token: JWT token to validate
            language: Language code for error messages
            
        Returns:
            dict: Token payload if valid
            
        Raises:
            AuthenticationError: If token is invalid
        """
        pass


class ISessionService(ABC):
    """Interface for session management service."""
    
    @abstractmethod
    async def create_session(self, user_id: int, token_id: str) -> str:
        """Create new session for user.
        
        Args:
            user_id: User ID
            token_id: Token identifier
            
        Returns:
            str: Session ID
        """
        pass
    
    @abstractmethod
    async def get_session(self, session_id: str) -> Optional[dict]:
        """Get session by ID.
        
        Args:
            session_id: Session ID
            
        Returns:
            Optional[dict]: Session data if found
        """
        pass
    
    @abstractmethod
    async def revoke_session(self, session_id: str) -> None:
        """Revoke session.
        
        Args:
            session_id: Session ID to revoke
        """
        pass
    
    @abstractmethod
    async def is_session_valid(self, session_id: str) -> bool:
        """Check if session is valid.
        
        Args:
            session_id: Session ID to check
            
        Returns:
            bool: True if session is valid
        """
        pass


class ICacheService(ABC):
    """Interface for cache service."""
    
    @abstractmethod
    async def get(self, key: str) -> Optional[str]:
        """Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Optional[str]: Cached value if found
        """
        pass
    
    @abstractmethod
    async def set(self, key: str, value: str, expire_seconds: Optional[int] = None) -> None:
        """Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            expire_seconds: Optional expiration time
        """
        pass
    
    @abstractmethod
    async def delete(self, key: str) -> None:
        """Delete value from cache.
        
        Args:
            key: Cache key to delete
        """
        pass
    
    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache.
        
        Args:
            key: Cache key to check
            
        Returns:
            bool: True if key exists
        """
        pass


class IOAuthService(ABC):
    """Interface for OAuth authentication service following DDD principles.
    
    This service handles OAuth 2.0 authentication with external providers
    using domain value objects and publishes domain events for audit trails.
    """
    
    @abstractmethod
    async def authenticate_with_oauth(
        self,
        provider: OAuthProvider,
        token: OAuthToken,
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> Tuple['User', 'OAuthProfile']:
        """Authenticate user via OAuth 2.0 and link or create a user profile.
        
        This method follows DDD principles by:
        - Using domain value objects for input validation
        - Accepting security context for audit trails
        - Publishing domain events for security monitoring
        - Following single responsibility principle
        - Supporting I18N for error messages
        
        Args:
            provider: OAuth provider value object
            token: OAuth token value object
            language: Language code for I18N error messages
            client_ip: Client IP address for security context
            user_agent: User agent string for security context
            correlation_id: Request correlation ID for tracing
            
        Returns:
            Tuple[User, OAuthProfile]: Authenticated user and OAuth profile
            
        Raises:
            AuthenticationError: If OAuth token or user info is invalid
        """
        pass
    
    @abstractmethod
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
        """
        pass 


class IUserLogoutService(ABC):
    """Interface for user logout service following DDD principles.
    
    This service handles user logout operations using domain value objects
    and publishes domain events for audit trails and security monitoring.
    """
    
    @abstractmethod
    async def logout_user(
        self,
        access_token: AccessToken,
        refresh_token: RefreshToken,
        user: User,
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> None:
        """Logout user by revoking tokens and terminating session.
        
        This method follows DDD principles by:
        - Using domain value objects for token validation
        - Accepting security context for audit trails
        - Publishing domain events for security monitoring
        - Following single responsibility principle
        - Supporting I18N for error messages
        
        Args:
            access_token: Access token value object (validated)
            refresh_token: Refresh token value object (validated)
            user: Authenticated user entity
            language: Language code for I18N error messages
            client_ip: Client IP address for security context
            user_agent: User agent string for security context
            correlation_id: Request correlation ID for tracing
            
        Raises:
            AuthenticationError: If token validation or revocation fails
        """
        pass 


class IPasswordEncryptionService(ABC):
    """Interface for password encryption service implementing defense-in-depth security.
    
    This service provides encryption-at-rest for password hashes, adding an additional
    security layer beyond bcrypt hashing. Even if database is compromised, encrypted
    password hashes remain protected without the encryption key.
    
    Security Features:
        - AES-256-GCM encryption with authenticated encryption
        - Key separation (encryption key different from database credentials)
        - Constant-time operations to prevent timing attacks
        - Secure key derivation and IV generation
    """
    
    @abstractmethod
    async def encrypt_password_hash(self, bcrypt_hash: str) -> str:
        """Encrypt a bcrypt password hash for secure database storage.
        
        Args:
            bcrypt_hash: The bcrypt-hashed password to encrypt
            
        Returns:
            str: Base64-encoded encrypted hash for database storage
            
        Raises:
            ValueError: If hash format is invalid
            EncryptionError: If encryption operation fails
        """
        pass
    
    @abstractmethod
    async def decrypt_password_hash(self, encrypted_hash: str) -> str:
        """Decrypt an encrypted password hash for verification.
        
        Args:
            encrypted_hash: Base64-encoded encrypted hash from database
            
        Returns:
            str: Decrypted bcrypt hash for password verification
            
        Raises:
            ValueError: If encrypted hash format is invalid
            DecryptionError: If decryption operation fails
        """
        pass
    
    @abstractmethod
    def is_encrypted_format(self, value: str) -> bool:
        """Check if a value is in encrypted format.
        
        Used for migration compatibility to detect legacy unencrypted hashes.
        
        Args:
            value: Value to check
            
        Returns:
            bool: True if value appears to be encrypted
        """
        pass 