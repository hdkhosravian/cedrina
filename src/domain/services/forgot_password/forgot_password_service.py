"""Forgot Password Service for secure password reset functionality.

This service orchestrates the complete forgot password workflow following Domain-Driven Design
principles, including user validation, secure token generation, email delivery, and password reset.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from pydantic import EmailStr, ValidationError

from src.core.exceptions import (
    EmailServiceError,
    ForgotPasswordError,
    PasswordResetError,
    RateLimitExceededError,
    UserNotFoundError,
)
from src.domain.entities.user import User
from src.domain.services.auth.password_reset_token_service import PasswordResetTokenService
from src.domain.services.forgot_password.password_reset_email_service import (
    PasswordResetEmailService,
)
from src.infrastructure.repositories.user_repository import UserRepository
from src.utils.i18n import get_translated_message
from src.utils.security import hash_password, validate_password_strength

logger = logging.getLogger(__name__)


class ForgotPasswordService:
    """Service for managing forgot password operations with enterprise-grade security.

    This service orchestrates the complete forgot password workflow, including:
    - Email validation and user lookup
    - Secure token generation and storage
    - Password reset email delivery
    - Token validation and password reset
    - Rate limiting and security monitoring

    The service follows Domain-Driven Design principles with clear separation
    of concerns and comprehensive error handling.
    """

    def __init__(
        self,
        user_repository: UserRepository,
        email_service: PasswordResetEmailService,
        token_service: Optional[PasswordResetTokenService] = None,
    ):
        """Initialize the ForgotPasswordService with required dependencies.

        Args:
            user_repository: Repository for user data operations
            email_service: Service for sending password reset emails
            token_service: Service for token operations (defaults to PasswordResetTokenService)
        """
        self.user_repository = user_repository
        self.email_service = email_service
        self.token_service = token_service or PasswordResetTokenService()

        # Rate limiting: minimum 5 minutes between password reset requests
        self._rate_limit_window = timedelta(minutes=5)
        self._last_request_times: dict[int, datetime] = {}

        logger.info("ForgotPasswordService initialized successfully")

    async def request_password_reset(self, email: EmailStr, language: str = "en") -> dict[str, str]:
        """Request a password reset for the given email address.

        This method handles the complete password reset request workflow:
        1. Validates the email format
        2. Checks rate limiting
        3. Looks up the user
        4. Generates a secure token
        5. Sends the password reset email

        Args:
            email: Email address to send password reset to
            language: Language code for email localization (default: "en")

        Returns:
            dict: Success message with localized content

        Raises:
            ValidationError: If email format is invalid
            RateLimitExceededError: If rate limit is exceeded
            UserNotFoundError: If user is not found or inactive
            EmailServiceError: If email delivery fails
            ForgotPasswordError: For other operational errors

        Security:
            - Rate limiting prevents abuse
            - Email enumeration protection via consistent error messages
            - Secure token generation with entropy validation
            - Comprehensive logging for security monitoring
        """
        try:
            # Step 1: Validate email format
            logger.info(f"Processing password reset request for email pattern: {email[:3]}***")

            # Step 2: Look up user and check rate limiting
            user = await self.user_repository.get_by_email(email)
            if user:
                await self._check_rate_limit_for_user(user, language)

            if not user:
                logger.warning(f"Password reset requested for non-existent email: {email}")
                # For security, return success message to prevent email enumeration
                return {
                    "message": get_translated_message("password_reset_email_sent", language),
                    "status": "success",
                }

            if not user.is_active:
                logger.warning(f"Password reset requested for inactive user: {user.id}")
                # For security, return success message to prevent account enumeration
                return {
                    "message": get_translated_message("password_reset_email_sent", language),
                    "status": "success",
                }

            # Step 3: Generate secure token
            token = self.token_service.generate_token(user)
            logger.info(f"Generated password reset token for user: {user.id}")

            # Step 4: Send password reset email
            try:
                await self.email_service.send_password_reset_email(
                    user=user,
                    token=token,
                    language=language,
                )
                logger.info(f"Password reset email sent successfully to user: {user.id}")

            except EmailServiceError as e:
                # Clear token if email fails
                self.token_service.invalidate_token(user, reason="email_delivery_failed")
                await self.user_repository.save(user)
                logger.error(f"Failed to send password reset email to user {user.id}: {str(e)}")
                raise EmailServiceError(
                    get_translated_message("password_reset_email_failed", language)
                ) from e

            # Step 5: Save user with token and update rate limiting
            await self.user_repository.save(user)
            self._update_rate_limit(user.id)

            return {
                "message": get_translated_message("password_reset_email_sent", language),
                "status": "success",
            }

        except (ValidationError, RateLimitExceededError, EmailServiceError) as e:
            # Re-raise known exceptions
            raise e

        except Exception as e:
            logger.error(f"Unexpected error in password reset request: {str(e)}")
            raise ForgotPasswordError(
                get_translated_message("password_reset_request_failed", language)
            ) from e

    async def reset_password(
        self, token: str, new_password: str, language: str = "en"
    ) -> dict[str, str]:
        """Reset user password using a valid token.

        This method handles the password reset workflow:
        1. Validates the token format and finds the associated user
        2. Verifies token validity and expiration
        3. Validates new password strength
        4. Updates the password and clears the token

        Args:
            token: Password reset token
            new_password: New password to set
            language: Language code for error messages (default: "en")

        Returns:
            dict: Success message with localized content

        Raises:
            PasswordResetError: If token is invalid, expired, or password is weak
            UserNotFoundError: If user associated with token is not found
            ForgotPasswordError: For other operational errors

        Security:
            - Token validation with timing attack protection
            - Password strength validation
            - Token cleanup after use (success or failure)
            - Comprehensive logging for security monitoring
        """
        try:
            logger.info(f"Processing password reset with token: {token[:8]}...")

            # Step 1: Validate token format (should be 64 hex characters)
            if not token or len(token) != 64 or not all(c in "0123456789abcdef" for c in token):
                logger.warning("Invalid password reset token format received")
                raise PasswordResetError(
                    get_translated_message("password_reset_token_invalid", language)
                )

            # Step 2: Find user with this token
            user = await self.user_repository.get_by_reset_token(token)
            if not user:
                logger.warning(f"Password reset attempted with unknown token: {token[:8]}...")
                raise PasswordResetError(
                    get_translated_message("password_reset_token_invalid", language)
                )

            # Step 3: Validate token
            if not self.token_service.is_token_valid(user, token):
                logger.warning(f"Invalid or expired password reset token for user: {user.id}")
                # Clear invalid token
                self.token_service.invalidate_token(user, reason="invalid_token_attempt")
                await self.user_repository.save(user)
                raise PasswordResetError(
                    get_translated_message("password_reset_token_invalid", language)
                )

            try:
                # Step 4: Validate new password strength
                if not validate_password_strength(new_password):
                    logger.warning(f"Weak password provided for user: {user.id}")
                    # Invalidate token even for weak password attempts (security)
                    self.token_service.invalidate_token(user, reason="weak_password_attempt")
                    await self.user_repository.save(user)
                    raise PasswordResetError(
                        get_translated_message("password_too_weak", language)
                    )

                # Step 5: Hash new password and update user
                user.hashed_password = hash_password(new_password)
                
                # Step 6: Invalidate token immediately (one-time use enforcement)
                self.token_service.invalidate_token(user, reason="password_reset_successful")

                # Step 7: Save changes
                await self.user_repository.save(user)

                logger.info(f"Password reset completed successfully for user: {user.id}")

                return {
                    "message": get_translated_message("password_reset_success", language),
                    "status": "success",
                }

            except PasswordResetError:
                # Don't double-invalidate token for password-related errors
                # Token was already invalidated above for weak passwords
                raise
            except Exception as e:
                # Ensure token is invalidated for other unexpected failures (security)
                self.token_service.invalidate_token(user, reason="reset_failed")
                await self.user_repository.save(user)
                raise e

        except (PasswordResetError, UserNotFoundError) as e:
            # Re-raise known exceptions
            raise e

        except Exception as e:
            logger.error(f"Unexpected error in password reset: {str(e)}")
            raise ForgotPasswordError(
                get_translated_message("password_reset_failed", language)
            ) from e

    async def cleanup_expired_tokens(self) -> int:
        """Clean up expired password reset tokens.

        This maintenance method removes expired tokens to keep the system clean
        and prevent unnecessary database storage.

        Returns:
            int: Number of expired tokens cleaned up

        Note:
            This method should be called periodically (e.g., via cron job)
            to maintain system hygiene.
        """
        try:
            logger.info("Starting cleanup of expired password reset tokens")

            cleaned_count = 0
            users_with_tokens = await self.user_repository.get_users_with_reset_tokens()

            for user in users_with_tokens:
                if self.token_service.is_token_expired(user):
                    self.token_service.invalidate_token(user, reason="expired_cleanup")
                    await self.user_repository.save(user)
                    cleaned_count += 1
                    logger.debug(f"Cleaned expired token for user: {user.id}")

            logger.info(f"Cleanup completed. Removed {cleaned_count} expired tokens")
            return cleaned_count

        except Exception as e:
            logger.error(f"Error during token cleanup: {str(e)}")
            raise ForgotPasswordError("Token cleanup failed") from e

    async def _check_rate_limit_for_user(self, user: User, language: str) -> None:
        """Check if the request exceeds rate limiting thresholds for a specific user.

        Args:
            user: User entity making the request
            language: Language for error messages

        Raises:
            RateLimitExceededError: If rate limit is exceeded
        """
        user_id = user.id
        now = datetime.now(timezone.utc)
        last_request = self._last_request_times.get(user_id)

        if last_request and (now - last_request) < self._rate_limit_window:
            logger.warning(f"Rate limit exceeded for user: {user_id}")
            raise RateLimitExceededError(
                get_translated_message("rate_limit_exceeded", language)
            )

    def _update_rate_limit(self, user_id: int) -> None:
        """Update the rate limiting timestamp for a user.

        Args:
            user_id: ID of the user to update
        """
        self._last_request_times[user_id] = datetime.now(timezone.utc)
 