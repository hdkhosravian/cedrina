"""Password Reset Service.

This domain service handles the execution of password resets using valid tokens,
following single responsibility principle and clean code practices.
"""

from datetime import datetime, timezone
from typing import Dict, Optional

import structlog

from src.core.exceptions import (
    ForgotPasswordError,
    PasswordResetError,
    UserNotFoundError,
)
from src.domain.entities.user import User
from src.domain.events.password_reset_events import (
    PasswordResetCompletedEvent,
    PasswordResetFailedEvent,
)
from src.domain.interfaces.repositories import IUserRepository
from src.domain.interfaces.services import (
    IEventPublisher,
    IPasswordResetTokenService,
)
from src.domain.value_objects.password import Password, HashedPassword
from src.domain.value_objects.reset_token import ResetToken
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class PasswordResetService:
    """Service for executing password resets with valid tokens.
    
    This service is responsible for:
    - Validating reset tokens
    - Validating new passwords
    - Updating user passwords
    - Invalidating tokens after use
    - Publishing domain events
    
    Follows single responsibility principle by focusing only on
    the execution phase of password reset workflow.
    """
    
    def __init__(
        self,
        user_repository: IUserRepository,
        token_service: IPasswordResetTokenService,
        event_publisher: IEventPublisher,
    ):
        """Initialize with required dependencies.
        
        Args:
            user_repository: Repository for user data operations
            token_service: Service for token validation and management
            event_publisher: Service for publishing domain events
        """
        self._user_repository = user_repository
        self._token_service = token_service
        self._event_publisher = event_publisher
        
        logger.info("PasswordResetService initialized")
    
    async def reset_password(
        self,
        token: str,
        new_password: str,
        language: str = "en",
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, str]:
        """Reset user password using a valid token.
        
        This method handles the complete password reset execution workflow:
        1. Validate token format
        2. Find user by token
        3. Validate token against user
        4. Validate new password strength
        5. Update password and invalidate token
        6. Publish domain events
        
        Args:
            token: Password reset token
            new_password: New password to set
            language: Language code for error messages
            user_agent: Optional user agent for security tracking
            ip_address: Optional IP address for security tracking
            correlation_id: Optional correlation ID for request tracking
            
        Returns:
            Dict containing success message and status
            
        Raises:
            PasswordResetError: If token is invalid, expired, or password is weak
            UserNotFoundError: If user associated with token is not found
            ForgotPasswordError: For other operational errors
            
        Security Features:
            - Token validation with timing attack protection
            - Password strength validation via value objects
            - One-time use token enforcement
            - Comprehensive audit logging via domain events
        """
        user: Optional[User] = None
        
        try:
            logger.info(
                "Processing password reset",
                token_prefix=token[:8] if token else "none",
                correlation_id=correlation_id
            )
            
            # Step 1: Validate token format and find user
            user = await self._validate_token_and_get_user(token, language)
            
            # Step 2: Validate token against user record
            await self._validate_token_against_user(user, token, language)
            
            # Step 3: Validate and create new password
            new_password_obj = self._validate_new_password(new_password, language)
            
            # Step 4: Update user password and invalidate token
            await self._update_user_password(user, new_password_obj)
            
            # Step 5: Publish success event
            await self._publish_success_event(
                user, user_agent, ip_address, correlation_id
            )
            
            logger.info(
                "Password reset completed successfully",
                user_id=user.id,
                correlation_id=correlation_id
            )
            
            return self._create_success_response(language)
            
        except (PasswordResetError, UserNotFoundError):
            # Re-raise known domain exceptions
            if user:
                await self._publish_failure_event(
                    user, "token_validation_failed", token[:8] if token else None,
                    user_agent, ip_address, correlation_id
                )
            raise
            
        except ValueError as e:
            # Handle password validation errors from value objects
            if user:
                self._token_service.invalidate_token(user, reason="weak_password_attempt")
                await self._user_repository.save(user)
                
                await self._publish_failure_event(
                    user, "weak_password", token[:8] if token else None,
                    user_agent, ip_address, correlation_id
                )
            
            logger.warning(
                "Password validation failed",
                error=str(e),
                user_id=user.id if user else None,
                correlation_id=correlation_id
            )
            
            raise PasswordResetError(
                get_translated_message("password_too_weak", language)
            ) from e
            
        except Exception as e:
            # Handle unexpected errors
            logger.error(
                "Unexpected error in password reset",
                error=str(e),
                user_id=user.id if user else None,
                correlation_id=correlation_id
            )
            
            if user:
                # Ensure token is invalidated for security
                self._token_service.invalidate_token(user, reason="reset_failed")
                await self._user_repository.save(user)
                
                await self._publish_failure_event(
                    user, "unexpected_error", token[:8] if token else None,
                    user_agent, ip_address, correlation_id
                )
            
            raise ForgotPasswordError(
                get_translated_message("password_reset_failed", language)
            ) from e
    
    async def _validate_token_and_get_user(
        self, token: str, language: str
    ) -> User:
        """Validate token format and find associated user.
        
        Args:
            token: Token to validate and lookup
            language: Language for error messages
            
        Returns:
            User: User entity associated with token
            
        Raises:
            PasswordResetError: If token format is invalid or user not found
        """
        # Validate token format using value object
        try:
            # This will raise ValueError if format is invalid
            ResetToken.from_existing(token, datetime.now(timezone.utc))
        except ValueError:
            logger.warning("Invalid token format received")
            raise PasswordResetError(
                get_translated_message("password_reset_token_invalid", language)
            )
        
        # Find user by token
        user = await self._user_repository.get_by_reset_token(token)
        if not user:
            logger.warning(
                "Password reset attempted with unknown token",
                token_prefix=token[:8]
            )
            raise PasswordResetError(
                get_translated_message("password_reset_token_invalid", language)
            )
        
        return user
    
    async def _validate_token_against_user(
        self, user: User, token: str, language: str
    ) -> None:
        """Validate token against user's stored token.
        
        Args:
            user: User entity with stored token
            token: Token to validate
            language: Language for error messages
            
        Raises:
            PasswordResetError: If token is invalid or expired
        """
        if not self._token_service.validate_token(user, token):
            logger.warning(
                "Invalid or expired password reset token",
                user_id=user.id,
                token_prefix=token[:8]
            )
            
            # Clear invalid/expired token
            self._token_service.invalidate_token(user, reason="invalid_token_attempt")
            await self._user_repository.save(user)
            
            raise PasswordResetError(
                get_translated_message("password_reset_token_invalid", language)
            )
    
    def _validate_new_password(self, new_password: str, language: str) -> Password:
        """Validate new password using Password value object.
        
        Args:
            new_password: Raw password string
            language: Language for error messages
            
        Returns:
            Password: Validated password value object
            
        Raises:
            ValueError: If password doesn't meet requirements (caught by caller)
        """
        # Password value object will validate strength on construction
        return Password(value=new_password)
    
    async def _update_user_password(
        self, user: User, new_password: Password
    ) -> None:
        """Update user password and invalidate token.
        
        Args:
            user: User entity to update
            new_password: New password value object
        """
        # Convert password to hashed format
        hashed_password = new_password.to_hashed()
        user.hashed_password = hashed_password.value
        
        # Invalidate token immediately (one-time use enforcement)
        self._token_service.invalidate_token(user, reason="password_reset_successful")
        
        # Save changes
        await self._user_repository.save(user)
    
    async def _publish_success_event(
        self,
        user: User,
        user_agent: Optional[str],
        ip_address: Optional[str],
        correlation_id: Optional[str],
    ) -> None:
        """Publish successful password reset event.
        
        Args:
            user: User entity
            user_agent: User agent string
            ip_address: IP address
            correlation_id: Correlation ID
        """
        event = PasswordResetCompletedEvent(
            occurred_at=datetime.now(timezone.utc),
            user_id=user.id,
            correlation_id=correlation_id,
            email=user.email,
            reset_method="token",
            user_agent=user_agent,
            ip_address=ip_address,
        )
        
        await self._event_publisher.publish(event)
    
    async def _publish_failure_event(
        self,
        user: User,
        failure_reason: str,
        token_used: Optional[str],
        user_agent: Optional[str],
        ip_address: Optional[str],
        correlation_id: Optional[str],
    ) -> None:
        """Publish password reset failure event.
        
        Args:
            user: User entity
            failure_reason: Reason for failure
            token_used: Masked token that was used
            user_agent: User agent string
            ip_address: IP address
            correlation_id: Correlation ID
        """
        event = PasswordResetFailedEvent(
            occurred_at=datetime.now(timezone.utc),
            user_id=user.id,
            correlation_id=correlation_id,
            email=user.email,
            failure_reason=failure_reason,
            token_used=f"{token_used}..." if token_used else None,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        
        await self._event_publisher.publish(event)
    
    def _create_success_response(self, language: str) -> Dict[str, str]:
        """Create standardized success response.
        
        Args:
            language: Language for message
            
        Returns:
            Dict containing success message and status
        """
        return {
            "message": get_translated_message("password_reset_success", language),
            "status": "success",
        } 