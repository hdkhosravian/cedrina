"""Service interfaces for domain services.

These interfaces define contracts for domain services,
enabling dependency inversion and better testability.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional

from pydantic import EmailStr

from src.domain.entities.user import User
from src.domain.events.password_reset_events import BaseDomainEvent
from src.domain.value_objects.reset_token import ResetToken


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
    def generate_token(self, user: User) -> ResetToken:
        """Generate a secure password reset token.
        
        Args:
            user: User to generate token for
            
        Returns:
            ResetToken: Generated token with expiration
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
    """Interface for user authentication service."""
    
    @abstractmethod
    async def authenticate_user(self, username: str, password: str) -> User:
        """Authenticate user with credentials.
        
        Args:
            username: Username for authentication
            password: Password for authentication
            
        Returns:
            User: Authenticated user entity
            
        Raises:
            AuthenticationError: If credentials are invalid
        """
        pass
    
    @abstractmethod
    async def verify_password(self, user: User, password: str) -> bool:
        """Verify password for user.
        
        Args:
            user: User entity
            password: Password to verify
            
        Returns:
            bool: True if password is correct
        """
        pass


class IUserRegistrationService(ABC):
    """Interface for user registration service."""
    
    @abstractmethod
    async def register_user(self, username: str, email: str, password: str) -> User:
        """Register a new user.
        
        Args:
            username: Desired username
            email: Email address
            password: Password
            
        Returns:
            User: Newly created user entity
            
        Raises:
            DuplicateUserError: If username or email already exists
            PasswordPolicyError: If password doesn't meet requirements
        """
        pass
    
    @abstractmethod
    async def check_username_availability(self, username: str) -> bool:
        """Check if username is available.
        
        Args:
            username: Username to check
            
        Returns:
            bool: True if username is available
        """
        pass
    
    @abstractmethod
    async def check_email_availability(self, email: str) -> bool:
        """Check if email is available.
        
        Args:
            email: Email to check
            
        Returns:
            bool: True if email is available
        """
        pass


class IPasswordChangeService(ABC):
    """Interface for password change service."""
    
    @abstractmethod
    async def change_password(
        self, 
        user_id: int, 
        old_password: str, 
        new_password: str
    ) -> None:
        """Change user password.
        
        Args:
            user_id: ID of user changing password
            old_password: Current password for verification
            new_password: New password to set
            
        Raises:
            AuthenticationError: If user not found or inactive
            InvalidOldPasswordError: If old password is incorrect
            PasswordReuseError: If new password same as old
            PasswordPolicyError: If new password doesn't meet requirements
        """
        pass


class ITokenService(ABC):
    """Interface for JWT token management service."""
    
    @abstractmethod
    async def create_access_token(self, user: User) -> str:
        """Create JWT access token for user.
        
        Args:
            user: User to create token for
            
        Returns:
            str: Encoded access token
        """
        pass
    
    @abstractmethod
    async def create_refresh_token(self, user: User) -> str:
        """Create JWT refresh token for user.
        
        Args:
            user: User to create token for
            
        Returns:
            str: Encoded refresh token
        """
        pass
    
    @abstractmethod
    async def refresh_tokens(self, refresh_token: str) -> dict:
        """Refresh access and refresh tokens.
        
        Args:
            refresh_token: Current refresh token
            
        Returns:
            dict: New access and refresh tokens
            
        Raises:
            AuthenticationError: If refresh token is invalid or expired
        """
        pass
    
    @abstractmethod
    async def validate_access_token(self, token: str) -> dict:
        """Validate access token and return claims.
        
        Args:
            token: Access token to validate
            
        Returns:
            dict: Token claims if valid
            
        Raises:
            AuthenticationError: If token is invalid or expired
        """
        pass
    
    @abstractmethod
    async def revoke_refresh_token(self, token: str) -> None:
        """Revoke refresh token.
        
        Args:
            token: Refresh token to revoke
        """
        pass


class ISessionService(ABC):
    """Interface for session management service."""
    
    @abstractmethod
    async def create_session(self, user_id: int, token_id: str) -> str:
        """Create user session.
        
        Args:
            user_id: User ID for session
            token_id: Token ID for session
            
        Returns:
            str: Session identifier
        """
        pass
    
    @abstractmethod
    async def get_session(self, session_id: str) -> Optional[dict]:
        """Get session by ID.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Optional[dict]: Session data if found
        """
        pass
    
    @abstractmethod
    async def revoke_session(self, session_id: str) -> None:
        """Revoke user session.
        
        Args:
            session_id: Session identifier to revoke
        """
        pass
    
    @abstractmethod
    async def is_session_valid(self, session_id: str) -> bool:
        """Check if session is valid.
        
        Args:
            session_id: Session identifier to check
            
        Returns:
            bool: True if session is valid
        """
        pass


class ICacheService(ABC):
    """Interface for cache service (Redis abstraction)."""
    
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
        """Delete key from cache.
        
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