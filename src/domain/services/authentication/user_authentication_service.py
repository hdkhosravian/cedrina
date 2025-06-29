"""User Authentication Domain Service.

This service handles user authentication operations following Domain-Driven Design
principles and single responsibility principle.
"""

from typing import Optional

import structlog

from src.core.exceptions import AuthenticationError
from src.domain.entities.user import User
from src.domain.events.authentication_events import (
    AuthenticationFailedEvent,
    UserLoggedInEvent,
)
from src.domain.interfaces.repositories import IUserRepository
from src.domain.interfaces.services import (
    IEventPublisher,
    IUserAuthenticationService,
)
from src.domain.value_objects.password import HashedPassword
from src.domain.value_objects.username import Username
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class UserAuthenticationService(IUserAuthenticationService):
    """Domain service for user authentication operations.
    
    This service handles only authentication-related operations,
    following the single responsibility principle from clean architecture.
    
    Responsibilities:
    - Authenticate users with username/password
    - Verify passwords for users
    - Publish authentication events
    - Handle authentication failures securely
    
    Security Features:
    - Timing attack protection via constant-time comparison
    - Comprehensive security event logging
    - Username normalization to prevent enumeration
    - Fail-secure authentication logic
    """
    
    def __init__(
        self,
        user_repository: IUserRepository,
        event_publisher: IEventPublisher,
    ):
        """Initialize authentication service with dependencies.
        
        Args:
            user_repository: Repository for user data access
            event_publisher: Publisher for domain events
        """
        self._user_repository = user_repository
        self._event_publisher = event_publisher
        
        logger.info("UserAuthenticationService initialized")
    
    async def authenticate_user(
        self,
        username: str,
        password: str,
        correlation_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> User:
        """Authenticate user with username and password.
        
        Args:
            username: Raw username string
            password: Raw password string  
            correlation_id: Optional correlation ID for tracking
            user_agent: Browser/client user agent
            ip_address: Client IP address
            
        Returns:
            User: Authenticated user entity
            
        Raises:
            AuthenticationError: If credentials are invalid or user inactive
        """
        try:
            # Normalize username using value object
            username_vo = Username(username)
            
            logger.info(
                "Authentication attempt started",
                username=username_vo.mask_for_logging(),
                correlation_id=correlation_id,
                ip_address=ip_address,
            )
            
            # Retrieve user by username
            user = await self._user_repository.get_by_username(str(username_vo))
            
            # Check if user exists and verify password
            if not user or not await self.verify_password(user, password):
                await self._handle_authentication_failure(
                    username_vo,
                    "invalid_credentials",
                    correlation_id,
                    user_agent,
                    ip_address,
                )
                raise AuthenticationError(
                    get_translated_message("invalid_username_or_password", "en")
                )
            
            # Check if user is active
            if not user.is_active:
                await self._handle_authentication_failure(
                    username_vo,
                    "user_inactive",
                    correlation_id,
                    user_agent,
                    ip_address,
                )
                raise AuthenticationError(
                    get_translated_message("user_account_inactive", "en")
                )
            
            # Successful authentication - publish event
            await self._publish_login_event(
                user,
                correlation_id,
                user_agent,
                ip_address,
            )
            
            logger.info(
                "Authentication successful",
                user_id=user.id,
                username=username_vo.mask_for_logging(),
                correlation_id=correlation_id,
            )
            
            return user
            
        except ValueError as e:
            # Username validation failed
            logger.warning(
                "Authentication failed - invalid username format",
                username=username[:3] + "***" if username else "None",
                error=str(e),
                correlation_id=correlation_id,
            )
            raise AuthenticationError(
                get_translated_message("invalid_username_or_password", "en")
            )
        except Exception as e:
            logger.error(
                "Unexpected authentication error",
                username=username[:3] + "***" if username else "None",
                error=str(e),
                correlation_id=correlation_id,
            )
            raise AuthenticationError(
                get_translated_message("authentication_system_error", "en")
            )
    
    async def verify_password(self, user: User, password: str) -> bool:
        """Verify password for user using constant-time comparison.
        
        Args:
            user: User entity with hashed password
            password: Plain text password to verify
            
        Returns:
            bool: True if password is correct
        """
        try:
            if not user.hashed_password or not password:
                return False
            
            # Use value object for secure password verification
            hashed_password = HashedPassword(user.hashed_password)
            return hashed_password.verify(password)
            
        except Exception as e:
            logger.error(
                "Password verification error",
                user_id=user.id,
                error=str(e),
            )
            return False
    
    async def _handle_authentication_failure(
        self,
        attempted_username: Username,
        failure_reason: str,
        correlation_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Handle authentication failure by publishing security event.
        
        Args:
            attempted_username: Username that was attempted
            failure_reason: Reason for authentication failure
            correlation_id: Optional correlation ID for tracking
            user_agent: Browser/client user agent
            ip_address: Client IP address
        """
        try:
            # Publish authentication failure event for security monitoring
            failure_event = AuthenticationFailedEvent.create(
                attempted_username=str(attempted_username),
                failure_reason=failure_reason,
                correlation_id=correlation_id,
                user_agent=user_agent,
                ip_address=ip_address,
            )
            
            await self._event_publisher.publish(failure_event)
            
            logger.warning(
                "Authentication failure event published",
                attempted_username=attempted_username.mask_for_logging(),
                failure_reason=failure_reason,
                correlation_id=correlation_id,
            )
            
        except Exception as e:
            logger.error(
                "Failed to publish authentication failure event",
                attempted_username=attempted_username.mask_for_logging(),
                error=str(e),
            )
    
    async def _publish_login_event(
        self,
        user: User,
        correlation_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Publish successful login event.
        
        Args:
            user: Authenticated user
            correlation_id: Optional correlation ID for tracking
            user_agent: Browser/client user agent
            ip_address: Client IP address
        """
        try:
            # Create and publish login event
            login_event = UserLoggedInEvent.create(
                user_id=user.id,
                username=user.username,
                correlation_id=correlation_id,
                user_agent=user_agent,
                ip_address=ip_address,
                previous_login_at=getattr(user, 'last_login_at', None),
            )
            
            await self._event_publisher.publish(login_event)
            
            logger.info(
                "Login event published",
                user_id=user.id,
                correlation_id=correlation_id,
            )
            
        except Exception as e:
            logger.error(
                "Failed to publish login event",
                user_id=user.id,
                error=str(e),
            ) 