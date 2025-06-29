"""Password Change Service following Domain-Driven Design principles.

This service handles password changes for authenticated users with comprehensive
security validation, domain events, and audit trails.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

import structlog

from src.core.exceptions import (
    AuthenticationError,
    InvalidOldPasswordError,
    PasswordPolicyError,
    PasswordReuseError,
)
from src.domain.entities.user import User
from src.domain.events.authentication_events import PasswordChangedEvent
from src.domain.interfaces.repositories import IUserRepository
from src.domain.interfaces.services import IEventPublisher, IPasswordChangeService
from src.domain.value_objects.password import Password
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class PasswordChangeService(IPasswordChangeService):
    """Clean architecture password change service following DDD principles.
    
    This service implements secure password change operations with:
    - Domain value object validation
    - Comprehensive security checks
    - Domain event publishing for audit trails
    - Proper error handling and logging
    - Clean separation of concerns
    
    The service follows Domain-Driven Design by:
    - Using Password value objects for validation
    - Publishing PasswordChangedEvent domain events
    - Delegating to repository interfaces
    - Maintaining business rule integrity
    - Providing rich audit information
    """
    
    def __init__(
        self,
        user_repository: IUserRepository,
        event_publisher: IEventPublisher,
    ):
        """Initialize password change service with dependencies.
        
        Args:
            user_repository: Repository for user data operations
            event_publisher: Service for publishing domain events
        """
        self._user_repository = user_repository
        self._event_publisher = event_publisher
        
        logger.info("PasswordChangeService initialized with clean architecture")

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
        
        This method implements secure password change following DDD principles:
        
        1. **Input Validation**: Uses domain value objects for validation
        2. **Business Rules**: Enforces password policies and security rules
        3. **Domain Events**: Publishes events for audit trails and monitoring
        4. **Security Context**: Captures security information for audit
        5. **Error Handling**: Provides clear, translated error messages
        
        Security Features:
        - Password value object validation
        - Old password verification
        - Password reuse prevention
        - Comprehensive audit logging
        - Domain event publishing
        
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
        # Generate correlation ID if not provided
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
            
        # Create structured logger with security context
        request_logger = logger.bind(
            correlation_id=correlation_id,
            user_id=user_id,
            client_ip=client_ip[:15] + "***" if len(client_ip) > 15 else client_ip,
            user_agent=user_agent[:50] + "***" if len(user_agent) > 50 else user_agent,
            operation="password_change"
        )
        
        request_logger.info(
            "Password change initiated",
            has_old_password=bool(old_password),
            has_new_password=bool(new_password)
        )
        
        try:
            # Step 1: Validate input parameters
            self._validate_input_parameters(old_password, new_password)
            
            # Step 2: Retrieve and validate user
            user = await self._get_and_validate_user(user_id, language, request_logger)
            
            # Step 3: Create domain value objects for password validation
            old_password_obj = Password(old_password)
            new_password_obj = Password(new_password)
            
            request_logger.debug("Domain value objects created successfully")
            
            # Step 4: Verify old password
            await self._verify_old_password(user, old_password_obj, language, request_logger)
            
            # Step 5: Check password reuse
            self._check_password_reuse(old_password_obj, new_password_obj, language, request_logger)
            
            # Step 6: Update user password
            await self._update_user_password(user, new_password_obj, request_logger)
            
            # Step 7: Publish domain event for audit trails
            await self._publish_password_changed_event(
                user, client_ip, user_agent, correlation_id, request_logger
            )
            
            request_logger.info(
                "Password change completed successfully",
                username=user.username[:3] + "***" if user.username else "unknown"
            )
            
        except (ValueError, AuthenticationError, InvalidOldPasswordError, 
                PasswordReuseError, PasswordPolicyError) as e:
            # Log security-relevant failures
            request_logger.warning(
                "Password change failed",
                error_type=type(e).__name__,
                error_message=str(e)
            )
            raise
            
        except Exception as e:
            # Log unexpected errors
            request_logger.error(
                "Password change failed with unexpected error",
                error_type=type(e).__name__,
                error_message=str(e)
            )
            raise AuthenticationError(
                get_translated_message("password_change_service_unavailable", language)
            ) from e

    def _validate_input_parameters(self, old_password: str, new_password: str) -> None:
        """Validate input parameters for password change.
        
        Args:
            old_password: Current password
            new_password: New password
            
        Raises:
            ValueError: If parameters are invalid
        """
        if old_password is None:
            raise ValueError("Old password cannot be None")
        if new_password is None:
            raise ValueError("New password cannot be None")
        if not old_password.strip():
            raise ValueError("Old password cannot be empty")
        if not new_password.strip():
            raise ValueError("New password cannot be empty")

    async def _get_and_validate_user(
        self, 
        user_id: int, 
        language: str, 
        request_logger: structlog.BoundLogger
    ) -> User:
        """Retrieve and validate user exists and is active.
        
        Args:
            user_id: User ID to retrieve
            language: Language for error messages
            request_logger: Bound logger for context
            
        Returns:
            User: Retrieved and validated user
            
        Raises:
            AuthenticationError: If user not found or inactive
        """
        user = await self._user_repository.get_by_id(user_id)
        if not user:
            request_logger.warning("Password change attempted for non-existent user")
            raise AuthenticationError(
                get_translated_message("user_not_found", language)
            )

        if not user.is_active:
            request_logger.warning(
                "Password change attempted for inactive user",
                username=user.username[:3] + "***" if user.username else "unknown"
            )
            raise AuthenticationError(
                get_translated_message("user_account_inactive", language)
            )
            
        return user

    async def _verify_old_password(
        self, 
        user: User, 
        old_password: Password, 
        language: str,
        request_logger: structlog.BoundLogger
    ) -> None:
        """Verify the old password is correct.
        
        Args:
            user: User entity
            old_password: Old password value object
            language: Language for error messages
            request_logger: Bound logger for context
            
        Raises:
            InvalidOldPasswordError: If old password is incorrect
        """
        if not old_password.verify_against_hash(user.hashed_password):
            request_logger.warning(
                "Invalid old password provided for password change",
                username=user.username[:3] + "***" if user.username else "unknown"
            )
            raise InvalidOldPasswordError(
                get_translated_message("invalid_old_password", language)
            )

    def _check_password_reuse(
        self, 
        old_password: Password, 
        new_password: Password, 
        language: str,
        request_logger: structlog.BoundLogger
    ) -> None:
        """Check if new password is different from old password.
        
        Args:
            old_password: Old password value object
            new_password: New password value object
            language: Language for error messages
            request_logger: Bound logger for context
            
        Raises:
            PasswordReuseError: If passwords are the same
        """
        if old_password.value == new_password.value:
            request_logger.warning("Password change attempted with same password")
            raise PasswordReuseError(
                get_translated_message("new_password_must_be_different", language)
            )

    async def _update_user_password(
        self, 
        user: User, 
        new_password: Password,
        request_logger: structlog.BoundLogger
    ) -> None:
        """Update user password in the repository.
        
        Args:
            user: User entity to update
            new_password: New password value object
            request_logger: Bound logger for context
        """
        # Hash the new password and update user
        user.hashed_password = new_password.to_hashed().value
        
        # Save to repository
        await self._user_repository.save(user)
        
        request_logger.debug("User password updated successfully")

    async def _publish_password_changed_event(
        self,
        user: User,
        client_ip: str,
        user_agent: str,
        correlation_id: str,
        request_logger: structlog.BoundLogger
    ) -> None:
        """Publish password changed domain event for audit trails.
        
        Args:
            user: User entity
            client_ip: Client IP address
            user_agent: User agent string
            correlation_id: Correlation ID
            request_logger: Bound logger for context
        """
        event = PasswordChangedEvent.create(
            user_id=user.id,
            username=user.username or "unknown",
            change_method="self_service",
            correlation_id=correlation_id,
            user_agent=user_agent,
            ip_address=client_ip,
            forced_change=False
        )
        
        await self._event_publisher.publish(event)
        
        request_logger.debug(
            "Password changed event published",
            event_type="PasswordChangedEvent"
        ) 