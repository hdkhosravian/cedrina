"""User Registration Domain Service.

This service handles user registration operations following Domain-Driven Design
principles and single responsibility principle.
"""

from typing import Optional

import structlog

from src.core.config.settings import settings
from src.core.exceptions import DuplicateUserError, PasswordPolicyError
from src.domain.entities.user import Role, User
from src.domain.events.authentication_events import UserRegisteredEvent
from src.domain.interfaces.repositories import IUserRepository
from src.domain.interfaces import (
    IEventPublisher,
    IUserRegistrationService,
    IEmailConfirmationService,
)
from src.domain.value_objects.email import Email
from src.domain.value_objects.password import HashedPassword, Password
from src.domain.value_objects.username import Username
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class UserRegistrationService(IUserRegistrationService):
    """Domain service for user registration operations.
    
    This service handles only registration-related operations,
    following the single responsibility principle from clean architecture.
    
    Responsibilities:
    - Register new users with validation
    - Check username and email availability
    - Handle email confirmation based on settings
    - Publish registration events
    - Enforce business rules for registration
    
    Security Features:
    - Strong password policy enforcement
    - Username and email validation
    - Duplicate prevention
    - Registration event logging
    - Email confirmation integration
    """
    
    def __init__(
        self,
        user_repository: IUserRepository,
        event_publisher: IEventPublisher,
        email_confirmation_service: Optional[IEmailConfirmationService] = None,
    ):
        """Initialize registration service with dependencies.
        
        Args:
            user_repository: Repository for user data access
            event_publisher: Publisher for domain events
            email_confirmation_service: Optional service for email confirmation
        """
        self._user_repository = user_repository
        self._event_publisher = event_publisher
        self._email_confirmation_service = email_confirmation_service
        
        logger.info("UserRegistrationService initialized")
    
    async def register_user(
        self,
        username: Username,
        email: Email,
        password: Password,
        language: str = "en",
        correlation_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        role: Role = Role.USER,
    ) -> User:
        """Register a new user with comprehensive validation.
        
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
            PasswordPolicyError: If password doesn't meet requirements
            ValueError: If input validation fails
        """
        try:
            logger.info(
                "User registration started",
                username=username.mask_for_logging(),
                email=email.mask_for_logging(),
                correlation_id=correlation_id,
                ip_address=ip_address,
            )
            
            # Check for existing username
            if not await self.check_username_availability(str(username)):
                logger.warning(
                    "Registration failed - username already exists",
                    username=username.mask_for_logging(),
                    correlation_id=correlation_id,
                )
                raise DuplicateUserError(
                    get_translated_message("username_already_registered", language)
                )
            
            # Check for existing email
            if not await self.check_email_availability(str(email)):
                logger.warning(
                    "Registration failed - email already exists",
                    email=email.mask_for_logging(),
                    correlation_id=correlation_id,
                )
                raise DuplicateUserError(
                    get_translated_message("email_already_registered", language)
                )
            
            # Create hashed password
            hashed_password = password.to_hashed()
            
            # Determine user activation status based on email confirmation setting
            is_active = not getattr(settings, 'EMAIL_CONFIRMATION_ENABLED', False)
            email_confirmed = not getattr(settings, 'EMAIL_CONFIRMATION_ENABLED', False)
            
            # Create user entity
            user = User(
                username=str(username),
                email=str(email),
                hashed_password=str(hashed_password),
                role=role,
                is_active=is_active,
                email_confirmed=email_confirmed,
            )
            
            # Save user to repository
            saved_user = await self._user_repository.save(user)
            
            # Send confirmation email if enabled
            if getattr(settings, 'EMAIL_CONFIRMATION_ENABLED', False) and self._email_confirmation_service:
                try:
                    await self._email_confirmation_service.send_confirmation_email(
                        saved_user, language
                    )
                    logger.info(
                        "Email confirmation sent for new user",
                        user_id=saved_user.id,
                        email=email.mask_for_logging(),
                        language=language
                    )
                except Exception as e:
                    logger.error(
                        "Failed to send email confirmation for new user",
                        user_id=saved_user.id,
                        email=email.mask_for_logging(),
                        error=str(e),
                        language=language
                    )
                    # Don't fail registration if email confirmation fails
                    # User can request resend later
            
            # Publish registration event
            await self._publish_registration_event(
                saved_user,
                correlation_id,
                user_agent,
                ip_address,
            )
            
            logger.info(
                "User registration successful",
                user_id=saved_user.id,
                username=username.mask_for_logging(),
                email=email.mask_for_logging(),
                is_active=is_active,
                email_confirmed=email_confirmed,
                correlation_id=correlation_id,
            )
            
            return saved_user
            
        except (DuplicateUserError, PasswordPolicyError):
            # Re-raise domain exceptions as-is
            raise
        except ValueError as e:
            # Input validation failed
            logger.warning(
                "Registration failed - validation error",
                username=str(username)[:3] + "***" if username else "None",
                email=str(email)[:3] + "***" if email else "None",
                error=str(e),
                correlation_id=correlation_id,
            )
            raise
        except Exception as e:
            logger.error(
                "Unexpected registration error",
                username=str(username)[:3] + "***" if username else "None",
                email=str(email)[:3] + "***" if email else "None",
                error=str(e),
                correlation_id=correlation_id,
            )
            raise
    
    async def check_username_availability(self, username: str) -> bool:
        """Check if username is available for registration.
        
        Args:
            username: Username to check
            
        Returns:
            bool: True if username is available
        """
        try:
            # Normalize username using value object
            username_vo = Username(username)
            
            # Check if user exists
            existing_user = await self._user_repository.get_by_username(str(username_vo))
            is_available = existing_user is None
            
            logger.debug(
                "Username availability check",
                username=username_vo.mask_for_logging(),
                available=is_available,
            )
            
            return is_available
            
        except ValueError:
            # Invalid username format
            return False
        except Exception as e:
            logger.error(
                "Username availability check error",
                username=username[:3] + "***" if username else "None",
                error=str(e),
            )
            return False
    
    async def check_email_availability(self, email: str) -> bool:
        """Check if email is available for registration.
        
        Args:
            email: Email to check
            
        Returns:
            bool: True if email is available
        """
        try:
            # Normalize email using value object
            email_vo = Email(email)
            
            # Check if user exists
            existing_user = await self._user_repository.get_by_email(str(email_vo))
            is_available = existing_user is None
            
            logger.debug(
                "Email availability check",
                email=email_vo.mask_for_logging(),
                available=is_available,
            )
            
            return is_available
            
        except ValueError:
            # Invalid email format
            return False
        except Exception as e:
            logger.error(
                "Email availability check error",
                email=email[:3] + "***" if email else "None",
                error=str(e),
            )
            return False
    
    async def _publish_registration_event(
        self,
        user: User,
        correlation_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Publish user registration event.
        
        Args:
            user: Newly registered user
            correlation_id: Optional correlation ID for tracking
            user_agent: Browser/client user agent
            ip_address: Client IP address
        """
        try:
            # Create and publish registration event
            registration_event = UserRegisteredEvent.create(
                user_id=user.id,
                username=user.username,
                email=user.email,
                role=user.role.value,
                correlation_id=correlation_id,
                user_agent=user_agent,
                ip_address=ip_address,
            )
            
            await self._event_publisher.publish(registration_event)
            
            logger.info(
                "Registration event published",
                user_id=user.id,
                correlation_id=correlation_id,
            )
            
        except Exception as e:
            logger.error(
                "Failed to publish registration event",
                user_id=user.id,
                error=str(e),
            ) 