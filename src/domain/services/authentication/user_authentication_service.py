"""User Authentication Domain Service.

This service handles user authentication operations following Domain-Driven Design
principles and single responsibility principle. It uses domain value objects for
input validation and publishes domain events for audit trails and security monitoring.

Key DDD Principles Applied:
- Domain Value Objects for input validation and business rules
- Domain Events for audit trails and security monitoring
- Single Responsibility Principle for authentication logic
- Dependency Inversion through interfaces
- Ubiquitous Language in method names and documentation
- Fail-Safe security patterns with timing attack protection
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
from src.domain.interfaces import (
    IEventPublisher,
    IUserAuthenticationService,
)
from src.domain.value_objects.password import HashedPassword, Password
from src.domain.value_objects.username import Username
from src.utils.i18n import get_translated_message
from src.core.config.settings import settings

logger = structlog.get_logger(__name__)


class UserAuthenticationService(IUserAuthenticationService):
    """Domain service for user authentication operations following DDD principles.

    This service encapsulates all authentication business logic and follows
    Domain-Driven Design principles:

    - **Single Responsibility**: Handles only authentication-related operations
    - **Domain Value Objects**: Uses Username and Password value objects for validation
    - **Domain Events**: Publishes events for audit trails and security monitoring
    - **Dependency Inversion**: Depends on abstractions (interfaces) not concretions
    - **Ubiquitous Language**: Method names reflect business domain concepts
    - **Fail-Safe Security**: Implements timing attack protection and secure logging

    Security Features:
    - Timing attack protection via constant-time comparison
    - Comprehensive security event logging with data masking
    - Username normalization to prevent enumeration attacks
    - Fail-secure authentication logic
    - Correlation ID tracking for request tracing
    - Security context capture (IP, User-Agent) for audit trails
    """

    def __init__(
        self,
        user_repository: IUserRepository,
        event_publisher: IEventPublisher,
    ):
        """Initialize authentication service with dependencies.

        Args:
            user_repository: Repository for user data access (abstraction)
            event_publisher: Publisher for domain events (abstraction)

        Note:
            Dependencies are injected through interfaces, following
            dependency inversion principle from SOLID.
        """
        self._user_repository = user_repository
        self._event_publisher = event_publisher

        logger.info(
            "UserAuthenticationService initialized",
            service_type="domain_service",
            responsibilities=["authentication", "password_verification", "event_publishing"],
        )

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

        This method implements the core authentication business logic following
        Domain-Driven Design principles:

        1. **Input Validation**: Uses domain value objects (Username, Password)
        2. **Business Rules**: Enforces authentication rules and user state checks
        3. **Security Context**: Captures security-relevant information for audit
        4. **Domain Events**: Publishes events for security monitoring and audit trails
        5. **Error Handling**: Provides meaningful error messages in ubiquitous language
        6. **Logging**: Implements secure logging with data masking and correlation
        7. **I18N Support**: Uses provided language for all error messages

        Authentication Flow:
        1. Validate and normalize username using domain value object
        2. Retrieve user from repository using normalized username
        3. Verify password using constant-time comparison
        4. Check user account status (active/inactive)
        5. Publish appropriate domain events (success/failure)
        6. Return authenticated user entity or raise domain exception

        Args:
            username: Username value object (validated and normalized)
            password: Password value object (validated)
            language: Language code for I18N error messages
            client_ip: Client IP address for security context and audit
            user_agent: User agent string for security context and audit
            correlation_id: Request correlation ID for tracing and debugging

        Returns:
            User: Authenticated user entity with all required attributes

        Raises:
            AuthenticationError: If credentials are invalid, user inactive, or
                               authentication system error occurs

        Security Considerations:
        - Timing attack protection via constant-time password verification
        - Username normalization prevents enumeration attacks
        - Comprehensive audit trails via domain events
        - Secure logging with sensitive data masking
        - Fail-secure error handling
        """
        try:
            # Log authentication attempt with security context
            logger.info(
                "Authentication attempt initiated",
                username=username.mask_for_logging(),
                correlation_id=correlation_id,
                client_ip=client_ip,
                user_agent_length=len(user_agent) if user_agent else 0,
                security_context_captured=True,
            )

            # Retrieve user by normalized username from repository
            user = await self._user_repository.get_by_username(str(username))

            # Verify user exists and password is correct
            if not user or not await self.verify_password(user, password):
                await self._handle_authentication_failure(
                    attempted_username=username,
                    failure_reason="invalid_credentials",
                    correlation_id=correlation_id,
                    user_agent=user_agent,
                    ip_address=client_ip,
                )
                raise AuthenticationError(
                    get_translated_message("invalid_username_or_password", language)
                )

            if settings.EMAIL_CONFIRMATION_ENABLED and not user.email_confirmed:
                await self._handle_authentication_failure(
                    attempted_username=username,
                    failure_reason="email_confirmation_required",
                    correlation_id=correlation_id,
                    user_agent=user_agent,
                    ip_address=client_ip,
                )
                raise AuthenticationError(
                    get_translated_message("email_confirmation_required", language)
                )

            if not user.is_active:
                await self._handle_authentication_failure(
                    attempted_username=username,
                    failure_reason="user_inactive",
                    correlation_id=correlation_id,
                    user_agent=user_agent,
                    ip_address=client_ip,
                )
                raise AuthenticationError(
                    get_translated_message("user_account_inactive", language)
                )

            # Authentication successful - publish domain event
            await self._publish_successful_login_event(
                user=user,
                correlation_id=correlation_id,
                user_agent=user_agent,
                ip_address=client_ip,
            )

            # Log successful authentication
            logger.info(
                "Authentication successful",
                user_id=user.id,
                username=username.mask_for_logging(),
                correlation_id=correlation_id,
                authentication_method="username_password",
            )

            return user

        except ValueError as e:
            # Handle value object validation errors
            logger.warning(
                "Authentication failed - invalid input format",
                username=username.mask_for_logging(),
                error=str(e),
                error_type="validation_error",
                correlation_id=correlation_id,
            )
            raise AuthenticationError(
                get_translated_message("invalid_username_or_password", language)
            )
        except AuthenticationError:
            # Re-raise domain exceptions to maintain proper error context
            raise
        except Exception as e:
            # Handle unexpected errors with secure logging
            logger.error(
                "Authentication failed - unexpected error",
                username=username.mask_for_logging(),
                error=str(e),
                error_type=type(e).__name__,
                correlation_id=correlation_id,
            )
            raise AuthenticationError(
                get_translated_message("authentication_system_error", language)
            )

    async def verify_password(self, user: User, password: Password) -> bool:
        """Verify password for user using domain value objects and constant-time comparison.

        This method implements secure password verification following security best practices:

        1. **Constant-Time Comparison**: Prevents timing attacks by using constant-time
           comparison algorithms
        2. **Domain Value Objects**: Uses Password value object for validation
        3. **Fail-Safe Logic**: Returns False for any error condition
        4. **Secure Logging**: Logs errors without exposing sensitive information

        Args:
            user: User entity containing hashed password
            password: Password value object to verify against user's hashed password

        Returns:
            bool: True if password matches user's hashed password, False otherwise

        Security Features:
        - Constant-time comparison prevents timing attacks
        - No sensitive data in logs
        - Fail-safe error handling
        - Domain value object validation
        """
        try:
            # Validate inputs
            if not user or not user.hashed_password or not password:
                logger.debug(
                    "Password verification failed - missing data",
                    user_id=user.id if user else None,
                    has_hashed_password=bool(user and user.hashed_password),
                    has_password=bool(password),
                )
                return False

            # Use domain value object for secure password verification
            # Delegate to the Password's verify_against_hash method for constant-time comparison
            is_valid = password.verify_against_hash(user.hashed_password)

            logger.debug(
                "Password verification completed",
                user_id=user.id,
                is_valid=is_valid,
                verification_method="constant_time_comparison",
            )

            return is_valid

        except Exception as e:
            # Log error without exposing sensitive information
            logger.error(
                "Password verification error",
                user_id=user.id if user else None,
                error=str(e),
                error_type=type(e).__name__,
            )
            return False

    async def _handle_authentication_failure(
        self,
        attempted_username: Username,
        failure_reason: str,
        correlation_id: str,
        user_agent: str,
        ip_address: str,
    ) -> None:
        """Handle authentication failure by publishing security domain event.

        This method publishes authentication failure events for security monitoring
        and audit trails. It follows the domain event pattern to decouple security
        monitoring from authentication logic.

        Args:
            attempted_username: Username that was attempted (value object)
            failure_reason: Reason for authentication failure (domain language)
            correlation_id: Request correlation ID for tracing
            user_agent: Browser/client user agent for security context
            ip_address: Client IP address for security context

        Domain Events Published:
        - AuthenticationFailedEvent: Contains security context and failure details
        """
        try:
            # Create and publish authentication failure domain event
            failure_event = AuthenticationFailedEvent.create(
                attempted_username=str(attempted_username),
                failure_reason=failure_reason,
                correlation_id=correlation_id,
                user_agent=user_agent,
                ip_address=ip_address,
            )

            await self._event_publisher.publish(failure_event)

            logger.info(
                "Authentication failure event published",
                attempted_username=attempted_username.mask_for_logging(),
                failure_reason=failure_reason,
                correlation_id=correlation_id,
                event_type="AuthenticationFailedEvent",
            )

        except Exception as e:
            # Log event publishing failure but don't fail authentication
            logger.error(
                "Failed to publish authentication failure event",
                attempted_username=attempted_username.mask_for_logging(),
                error=str(e),
                correlation_id=correlation_id,
            )

    async def _publish_successful_login_event(
        self,
        user: User,
        correlation_id: str,
        user_agent: str,
        ip_address: str,
    ) -> None:
        """Publish successful login domain event for audit trails.

        This method publishes successful login events for audit trails and
        security monitoring. It captures important security context information
        for compliance and monitoring purposes.

        Args:
            user: Successfully authenticated user entity
            correlation_id: Request correlation ID for tracing
            user_agent: Browser/client user agent for security context
            ip_address: Client IP address for security context

        Domain Events Published:
        - UserLoggedInEvent: Contains user information and security context
        """
        try:
            # Create and publish successful login domain event
            login_event = UserLoggedInEvent.create(
                user_id=user.id,
                username=user.username,
                correlation_id=correlation_id,
                user_agent=user_agent,
                ip_address=ip_address,
                previous_login_at=getattr(user, "last_login_at", None),
            )

            await self._event_publisher.publish(login_event)

            logger.info(
                "Login event published successfully",
                user_id=user.id,
                correlation_id=correlation_id,
                event_type="UserLoggedInEvent",
            )

        except Exception as e:
            # Log event publishing failure but don't fail authentication
            logger.error(
                "Failed to publish login event",
                user_id=user.id,
                error=str(e),
                correlation_id=correlation_id,
            )
