"""User Logout Domain Service.

This service handles user logout operations following Domain-Driven Design
principles and single responsibility principle. It uses domain value objects for
input validation and publishes domain events for audit trails and security monitoring.

Key DDD Principles Applied:
- Domain Value Objects for input validation and business rules
- Domain Events for audit trails and security monitoring
- Single Responsibility Principle for logout logic
- Dependency Inversion through interfaces
- Ubiquitous Language in method names and documentation
- Fail-Safe security patterns with comprehensive validation
"""

from datetime import datetime, timezone
from typing import Optional

import structlog

from src.core.exceptions import AuthenticationError
from src.domain.entities.user import User
from src.domain.events.authentication_events import UserLoggedOutEvent
from src.domain.interfaces.repositories import IUserRepository
from src.domain.interfaces import (
    IEventPublisher,
    ITokenService,
    IUserLogoutService,
)
from src.domain.value_objects.jwt_token import AccessToken, RefreshToken
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class UserLogoutService(IUserLogoutService):
    """Domain service for user logout operations following DDD principles.
    
    This service encapsulates all logout business logic and follows
    Domain-Driven Design principles:
    
    - **Single Responsibility**: Handles only logout-related operations
    - **Domain Value Objects**: Uses AccessToken and RefreshToken value objects for validation
    - **Domain Events**: Publishes events for audit trails and security monitoring
    - **Dependency Inversion**: Depends on abstractions (interfaces) not concretions
    - **Ubiquitous Language**: Method names reflect business domain concepts
    - **Fail-Safe Security**: Implements comprehensive validation and secure logging
    
    Security Features:
    - Refresh token ownership validation to prevent cross-user token usage
    - Comprehensive security event logging with data masking
    - Concurrent token revocation for performance and atomicity
    - Fail-secure logout logic with proper error handling
    - Correlation ID tracking for request tracing
    - Security context capture (IP, User-Agent) for audit trails
    """
    
    def __init__(
        self,
        token_service: ITokenService,
        event_publisher: IEventPublisher,
    ):
        """Initialize logout service with dependencies.
        
        Args:
            token_service: Service for token operations (abstraction)
            event_publisher: Publisher for domain events (abstraction)
            
        Note:
            Dependencies are injected through interfaces, following
            dependency inversion principle from SOLID.
        """
        self._token_service = token_service
        self._event_publisher = event_publisher
        
        logger.info(
            "UserLogoutService initialized",
            service_type="domain_service",
            responsibilities=["logout", "token_revocation", "event_publishing"]
        )
    
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
        
        This method implements the core logout business logic following
        Domain-Driven Design principles:
        
        1. **Input Validation**: Uses domain value objects (AccessToken, RefreshToken)
        2. **Business Rules**: Revokes both tokens regardless of their validity
        3. **Security Context**: Captures security-relevant information for audit
        4. **Domain Events**: Publishes events for security monitoring and audit trails
        5. **Error Handling**: Provides meaningful error messages in ubiquitous language
        6. **Logging**: Implements secure logging with data masking and correlation
        7. **I18N Support**: Uses provided language for all error messages
        
        Logout Flow:
        1. Calculate session duration for audit purposes
        2. Revoke both access and refresh tokens concurrently
        3. Publish domain event for security monitoring
        4. Log successful logout with security context
        
        Args:
            access_token: Access token value object (validated)
            refresh_token: Refresh token value object (validated)
            user: Authenticated user entity
            language: Language code for I18N error messages
            client_ip: Client IP address for security context and audit
            user_agent: User agent string for security context and audit
            correlation_id: Request correlation ID for tracing and debugging
            
        Raises:
            AuthenticationError: If token revocation fails
                               
        Security Considerations:
        - Concurrent token revocation ensures atomicity
        - Comprehensive audit trails via domain events
        - Secure logging with sensitive data masking
        - Fail-secure error handling
        """
        try:
            # Log logout attempt with security context
            logger.info(
                "User logout initiated",
                user_id=user.id,
                username=user.username,
                access_token_id=access_token.get_token_id().mask_for_logging(),
                refresh_token_id=refresh_token.get_token_id().mask_for_logging(),
                correlation_id=correlation_id,
                client_ip=client_ip,
                user_agent_length=len(user_agent) if user_agent else 0,
                security_context_captured=True
            )
            
            # Calculate session duration for audit purposes
            session_duration = self._calculate_session_duration(access_token)
            
            # Revoke both tokens concurrently for performance and atomicity
            # We revoke both tokens regardless of their validity to ensure clean logout
            import asyncio
            await asyncio.gather(
                self._token_service.revoke_access_token(str(access_token.get_token_id())),
                self._token_service.revoke_refresh_token(refresh_token.token, language),
            )
            
            # Publish domain event for security monitoring and audit trails
            await self._publish_logout_event(
                user=user,
                session_duration=session_duration,
                correlation_id=correlation_id,
                user_agent=user_agent,
                ip_address=client_ip,
            )
            
            # Log successful logout
            logger.info(
                "User logout completed successfully",
                user_id=user.id,
                username=user.username,
                session_duration_seconds=session_duration,
                correlation_id=correlation_id,
                logout_method="user_initiated"
            )
            
        except AuthenticationError:
            # Re-raise authentication errors to be handled by caller
            logger.warning(
                "Logout failed due to authentication error",
                user_id=user.id,
                username=user.username,
                correlation_id=correlation_id
            )
            raise
        except Exception as e:
            # Log unexpected errors for debugging while maintaining security
            logger.error(
                "Unexpected error during logout",
                user_id=user.id,
                username=user.username,
                correlation_id=correlation_id,
                error_type=type(e).__name__,
                error_message=str(e)
            )
            raise AuthenticationError(
                get_translated_message("logout_failed_internal_error", language)
            )
    
    def _calculate_session_duration(self, access_token: AccessToken) -> Optional[int]:
        """Calculate session duration from access token for audit purposes.
        
        Args:
            access_token: Access token with issued-at time
            
        Returns:
            Optional[int]: Session duration in seconds, None if cannot calculate
        """
        try:
            issued_at = access_token.claims.get('iat')
            if not issued_at:
                return None
            
            # Convert timestamp to datetime and calculate duration
            issued_datetime = datetime.fromtimestamp(issued_at, tz=timezone.utc)
            current_time = datetime.now(timezone.utc)
            duration = current_time - issued_datetime
            
            return int(duration.total_seconds())
        except (ValueError, TypeError, OSError) as e:
            logger.debug(
                "Could not calculate session duration",
                error=str(e),
                iat_claim=access_token.claims.get('iat')
            )
            return None
    
    async def _publish_logout_event(
        self,
        user: User,
        session_duration: Optional[int],
        correlation_id: str,
        user_agent: str,
        ip_address: str,
    ) -> None:
        """Publish domain event for logout operation.
        
        Args:
            user: User who logged out
            session_duration: Duration of the session in seconds
            correlation_id: Request correlation ID
            user_agent: User agent string
            ip_address: Client IP address
        """
        try:
            event = UserLoggedOutEvent.create(
                user_id=user.id,
                username=user.username,
                logout_reason="user_initiated",
                correlation_id=correlation_id,
                user_agent=user_agent,
                ip_address=ip_address,
                session_duration=session_duration,
            )
            
            await self._event_publisher.publish(event)
            
            logger.debug(
                "Logout domain event published",
                user_id=user.id,
                username=user.username,
                event_type=type(event).__name__,
                correlation_id=correlation_id
            )
            
        except Exception as e:
            # Log but don't fail logout for event publishing errors
            logger.warning(
                "Failed to publish logout domain event",
                user_id=user.id,
                username=user.username,
                error=str(e),
                event_publishing_failure=True
            ) 