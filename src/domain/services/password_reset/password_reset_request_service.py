"""Password Reset Request Service.

This domain service handles the initiation of password reset requests,
following single responsibility principle and clean code practices.
"""

from datetime import datetime, timezone
from typing import Dict, Optional

import structlog
from pydantic import EmailStr

from src.core.exceptions import (
    EmailServiceError,
    ForgotPasswordError,
    RateLimitExceededError,
    UserNotFoundError,
)
from src.domain.entities.user import User
from src.domain.events.password_reset_events import (
    PasswordResetRequestedEvent,
    PasswordResetFailedEvent,
)
from src.domain.interfaces.repositories import IUserRepository
from src.domain.interfaces.services import (
    IEventPublisher,
    IPasswordResetEmailService,
    IPasswordResetTokenService,
    IRateLimitingService,
)
from src.domain.value_objects.reset_token import ResetToken
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class PasswordResetRequestService:
    """Service for handling password reset requests.
    
    This service is responsible for:
    - Validating reset requests
    - Checking rate limits
    - Generating secure tokens
    - Coordinating email delivery
    - Publishing domain events
    
    Follows single responsibility principle by focusing only on
    the request phase of password reset workflow.
    """
    
    def __init__(
        self,
        user_repository: IUserRepository,
        rate_limiting_service: IRateLimitingService,
        token_service: IPasswordResetTokenService,
        email_service: IPasswordResetEmailService,
        event_publisher: IEventPublisher,
    ):
        """Initialize with required dependencies.
        
        Args:
            user_repository: Repository for user data operations
            rate_limiting_service: Service for rate limiting checks
            token_service: Service for token generation and management
            email_service: Service for sending password reset emails
            event_publisher: Service for publishing domain events
        """
        self._user_repository = user_repository
        self._rate_limiting_service = rate_limiting_service
        self._token_service = token_service
        self._email_service = email_service
        self._event_publisher = event_publisher
        
        logger.info("PasswordResetRequestService initialized")
    
    async def request_password_reset(
        self,
        email: EmailStr,
        language: str = "en",
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, str]:
        """Request a password reset for the given email address.
        
        This method orchestrates the complete password reset request workflow:
        1. Look up the user
        2. Check rate limits
        3. Generate secure token
        4. Send reset email
        5. Publish domain events
        
        Args:
            email: Email address to send password reset to
            language: Language code for email localization
            user_agent: Optional user agent for security tracking
            ip_address: Optional IP address for security tracking
            correlation_id: Optional correlation ID for request tracking
            
        Returns:
            Dict containing success message and status
            
        Raises:
            RateLimitExceededError: If rate limit is exceeded
            EmailServiceError: If email delivery fails
            ForgotPasswordError: For other operational errors
            
        Security Features:
            - Rate limiting to prevent abuse
            - Email enumeration protection via consistent responses
            - Comprehensive audit logging via domain events
            - Secure token generation with proper entropy
        """
        try:
            logger.info(
                "Processing password reset request",
                email_prefix=email[:3],
                language=language,
                correlation_id=correlation_id
            )
            
            # Step 1: Look up user
            user = await self._user_repository.get_by_email(email)
            
            # Step 2: Security checks - rate limiting for existing users
            if user:
                await self._check_rate_limit_for_user(user, language)
            
            # Step 3: Handle non-existent or inactive users securely
            if not user or not user.is_active:
                await self._handle_invalid_user_request(
                    email, language, user_agent, ip_address, correlation_id
                )
                # Return success to prevent email enumeration
                return self._create_success_response(language)
            
            # Step 4: Generate secure token and update user
            token = self._token_service.generate_token(user)
            await self._update_user_with_token(user, token)
            
            # Step 5: Send password reset email
            await self._send_reset_email(user, token, language)
            
            # Step 6: Record rate limiting attempt
            await self._rate_limiting_service.record_attempt(user.id)
            
            # Step 7: Publish success event
            await self._publish_success_event(
                user, email, token, language, user_agent, ip_address, correlation_id
            )
            
            logger.info(
                "Password reset request completed successfully",
                user_id=user.id,
                correlation_id=correlation_id
            )
            
            return self._create_success_response(language)
            
        except RateLimitExceededError:
            # Re-raise rate limit errors as-is
            raise
            
        except EmailServiceError as e:
            # Handle email delivery failures
            if user:
                await self._handle_email_failure(user, token, language, correlation_id)
            raise e
            
        except Exception as e:
            # Handle unexpected errors
            logger.error(
                "Unexpected error in password reset request",
                error=str(e),
                correlation_id=correlation_id
            )
            
            if user:
                await self._publish_failure_event(
                    user, email, "unexpected_error", 
                    user_agent, ip_address, correlation_id
                )
            
            raise ForgotPasswordError(
                get_translated_message("password_reset_request_failed", language)
            ) from e
    
    async def _check_rate_limit_for_user(self, user: User, language: str) -> None:
        """Check rate limits for a specific user.
        
        Args:
            user: User making the request
            language: Language for error messages
            
        Raises:
            RateLimitExceededError: If rate limit is exceeded
        """
        if await self._rate_limiting_service.is_user_rate_limited(user.id):
            logger.warning("Rate limit exceeded", user_id=user.id)
            raise RateLimitExceededError(
                get_translated_message("rate_limit_exceeded", language)
            )
    
    async def _handle_invalid_user_request(
        self,
        email: EmailStr,
        language: str,
        user_agent: Optional[str],
        ip_address: Optional[str],
        correlation_id: Optional[str],
    ) -> None:
        """Handle requests for non-existent or inactive users.
        
        Args:
            email: Email address from request
            language: Language for logging
            user_agent: User agent for security tracking
            ip_address: IP address for security tracking
            correlation_id: Correlation ID for tracking
        """
        logger.warning(
            "Password reset requested for invalid user",
            email_prefix=email[:3],
            correlation_id=correlation_id
        )
        
        # Note: We don't publish events for non-existent users
        # to avoid leaking information about user existence
    
    async def _update_user_with_token(self, user: User, token: ResetToken) -> None:
        """Update user entity with new reset token.
        
        Args:
            user: User entity to update
            token: Reset token to set
        """
        user.password_reset_token = token.value
        user.password_reset_token_expires_at = token.expires_at
        await self._user_repository.save(user)
    
    async def _send_reset_email(
        self, user: User, token: ResetToken, language: str
    ) -> None:
        """Send password reset email to user.
        
        Args:
            user: User to send email to
            token: Reset token to include
            language: Language for email content
            
        Raises:
            EmailServiceError: If email delivery fails
        """
        try:
            success = await self._email_service.send_password_reset_email(
                user=user,
                token=token,
                language=language,
            )
            
            if not success:
                raise EmailServiceError("Email delivery returned failure status")
                
        except Exception as e:
            logger.error(
                "Failed to send password reset email",
                user_id=user.id,
                error=str(e)
            )
            raise EmailServiceError(
                get_translated_message("password_reset_email_failed", language)
            ) from e
    
    async def _handle_email_failure(
        self, user: User, token: ResetToken, language: str, correlation_id: Optional[str]
    ) -> None:
        """Handle email delivery failures by cleaning up token.
        
        Args:
            user: User entity
            token: Token that was generated
            language: Language for messages
            correlation_id: Correlation ID for tracking
        """
        # Clean up token if email fails
        self._token_service.invalidate_token(user, reason="email_delivery_failed")
        await self._user_repository.save(user)
        
        # Publish failure event
        await self._publish_failure_event(
            user, user.email, "email_delivery_failed", 
            None, None, correlation_id
        )
    
    async def _publish_success_event(
        self,
        user: User,
        email: EmailStr,
        token: ResetToken,
        language: str,
        user_agent: Optional[str],
        ip_address: Optional[str],
        correlation_id: Optional[str],
    ) -> None:
        """Publish successful password reset request event.
        
        Args:
            user: User entity
            email: Email address
            token: Generated token
            language: Language used
            user_agent: User agent string  
            ip_address: IP address
            correlation_id: Correlation ID
        """
        event = PasswordResetRequestedEvent(
            occurred_at=datetime.now(timezone.utc),
            user_id=user.id,
            correlation_id=correlation_id,
            email=email,
            token_expires_at=token.expires_at,
            language=language,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        
        await self._event_publisher.publish(event)
    
    async def _publish_failure_event(
        self,
        user: User,
        email: EmailStr,
        failure_reason: str,
        user_agent: Optional[str],
        ip_address: Optional[str],
        correlation_id: Optional[str],
    ) -> None:
        """Publish password reset failure event.
        
        Args:
            user: User entity
            email: Email address
            failure_reason: Reason for failure
            user_agent: User agent string
            ip_address: IP address  
            correlation_id: Correlation ID
        """
        event = PasswordResetFailedEvent(
            occurred_at=datetime.now(timezone.utc),
            user_id=user.id,
            correlation_id=correlation_id,
            email=email,
            failure_reason=failure_reason,
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
            "message": get_translated_message("password_reset_email_sent", language),
            "status": "success",
        } 