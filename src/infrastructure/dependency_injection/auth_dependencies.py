"""Clean Architecture Dependencies for Authentication.

This module provides dependency injection for clean authentication services
following Domain-Driven Design principles and dependency inversion.

Key DDD Principles Applied:
- Dependency Inversion through interfaces
- Single Responsibility for each factory
- Clean separation of infrastructure and domain concerns
- Proper abstraction layers
- Testable dependency injection

The dependency injection follows clean architecture by:
1. Defining clear interfaces for all dependencies
2. Implementing concrete factories for each service
3. Using dependency injection for loose coupling
4. Supporting both development and production configurations
5. Maintaining separation between infrastructure and domain layers
"""

from typing import Annotated

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.interfaces.repositories import IUserRepository
from src.domain.interfaces import (
    IEventPublisher,
    IOAuthService,
    IPasswordChangeService,
    IPasswordResetEmailService,
    IPasswordResetTokenService,
    IEmailConfirmationTokenService,
    IEmailConfirmationEmailService,
    IRateLimitingService,
    ITokenService,
    IUserAuthenticationService,
    IUserLogoutService,
    IUserRegistrationService,
)
from src.infrastructure.services.authentication.token import TokenService as LegacyTokenService
from src.domain.services.authentication.oauth_service import OAuthAuthenticationService
from src.domain.services.authentication.password_change_service import (
    PasswordChangeService,
)
from src.domain.services.authentication.user_authentication_security_service import (
    UserAuthenticationSecurityService,
)
from src.domain.services.authentication.user_logout_service import (
    UserLogoutService,
)
from src.domain.services.authentication.user_registration_service import (
    UserRegistrationService,
)
from src.domain.services.password_reset.password_reset_request_service import (
    PasswordResetRequestService,
)
from src.domain.services.password_reset.password_reset_service import (
    PasswordResetService,
)
from src.core.rate_limiting.password_reset_service import (
    RateLimitingService,
)
from src.infrastructure.database.async_db import get_async_db
from src.infrastructure.redis import get_redis
from src.infrastructure.repositories.user_repository import UserRepository
from src.infrastructure.services.event_publisher import InMemoryEventPublisher
from src.infrastructure.services.password_reset_email_service import (
    PasswordResetEmailService,
)
from src.infrastructure.services.password_reset_token_service import (
    PasswordResetTokenService,
)
from src.infrastructure.services.email_confirmation_token_service import (
    EmailConfirmationTokenService,
)
from src.infrastructure.services.email_confirmation_email_service import (
    EmailConfirmationEmailService,
)
from src.domain.services.email_confirmation.email_confirmation_request_service import (
    EmailConfirmationRequestService,
)
from src.domain.services.email_confirmation.email_confirmation_service import (
    EmailConfirmationService,
)
from src.infrastructure.services.token_service_adapter import TokenServiceAdapter

# ---------------------------------------------------------------------------
# Type aliases for dependency injection
# ---------------------------------------------------------------------------

AsyncDB = Annotated[AsyncSession, Depends(get_async_db)]
RedisClient = Annotated[Redis, Depends(get_redis)]

# ---------------------------------------------------------------------------
# Infrastructure Layer Dependencies
# ---------------------------------------------------------------------------


def get_user_repository(db: AsyncDB) -> IUserRepository:
    """Factory that returns user repository implementation.
    
    This factory creates a concrete implementation of the user repository
    interface, providing data access abstraction for domain services.
    
    Args:
        db: Database session dependency from FastAPI
        
    Returns:
        IUserRepository: Clean user repository implementation
        
    Note:
        The repository is created with a database session, following
        dependency injection principles. This allows for easy testing
        and configuration changes.
    """
    return UserRepository(db)


def get_event_publisher() -> IEventPublisher:
    """Factory that returns event publisher implementation.
    
    This factory creates an event publisher for domain events, supporting
    audit trails and security monitoring.
    
    Returns:
        IEventPublisher: Event publisher for domain events
        
    Note:
        In production, this could be configured to return:
        - Redis pub/sub implementation for distributed systems
        - RabbitMQ implementation for message queuing
        - Kafka implementation for event streaming
        - Database implementation for audit trails
        Currently returns in-memory implementation for development
    """
    return InMemoryEventPublisher()


def get_token_service(
    db: AsyncDB,
    redis: RedisClient,
) -> ITokenService:
    """Factory that returns clean token service implementation.
    
    This factory creates a token service adapter that wraps the existing
    legacy token service to work with clean architecture while maintaining
    compatibility with existing infrastructure.
    
    Args:
        db: Database session dependency for token storage
        redis: Redis client dependency for token caching
        
    Returns:
        ITokenService: Clean token service implementation
        
    Note:
        This adapter pattern allows us to gradually migrate from legacy
        token service to clean architecture without breaking existing
        functionality. The adapter implements the clean interface while
        delegating to the legacy implementation.
    """
    # Create legacy token service with infrastructure dependencies
    legacy_service = LegacyTokenService(db, redis)
    
    # Wrap with adapter for clean architecture compatibility
    return TokenServiceAdapter(legacy_service)


# ---------------------------------------------------------------------------
# Domain Service Dependencies
# ---------------------------------------------------------------------------


def get_user_authentication_service(
    user_repository: IUserRepository = Depends(get_user_repository),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> IUserAuthenticationService:
    """Factory that returns enhanced user authentication service with security logging.
    
    This factory creates the enhanced domain authentication service with its
    dependencies, following dependency injection principles. The enhanced service
    includes comprehensive security logging, error standardization, and information
    disclosure prevention.
    
    Args:
        user_repository: User repository dependency for data access
        event_publisher: Event publisher dependency for domain events
        
    Returns:
        IUserAuthenticationService: Enhanced authentication service with security features
        
    Note:
        The enhanced authentication service implements enterprise-grade security:
        - Zero-trust data masking for audit trails
        - Consistent error responses to prevent enumeration
        - Standardized timing to prevent timing attacks
        - Comprehensive security event logging
        - Risk-based authentication analysis
    """
    return UserAuthenticationSecurityService(
        user_repository=user_repository,
        event_publisher=event_publisher,
    )


def get_user_registration_service(
    user_repository: IUserRepository = Depends(get_user_repository),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> IUserRegistrationService:
    """Factory that returns clean user registration service.
    
    This factory creates the domain registration service with its
    dependencies, following dependency injection principles.
    
    Args:
        user_repository: User repository dependency for data access
        event_publisher: Event publisher dependency for domain events
        
    Returns:
        IUserRegistrationService: Clean registration service
        
    Note:
        The registration service depends on abstractions (interfaces)
        rather than concrete implementations, following dependency
        inversion principle from SOLID.
    """
    return UserRegistrationService(
        user_repository=user_repository,
        event_publisher=event_publisher,
    )


def get_oauth_service(
    user_repository: IUserRepository = Depends(get_user_repository),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> IOAuthService:
    """Factory that returns clean OAuth service implementation.
    
    This factory creates the domain OAuth service with its dependencies,
    following dependency injection principles.
    
    Args:
        user_repository: User repository dependency for data access
        event_publisher: Event publisher dependency for domain events
        
    Returns:
        IOAuthService: Clean OAuth service implementation
        
    Note:
        The OAuth service depends on abstractions (interfaces) rather than
        concrete implementations, following dependency inversion principle
        from SOLID. Currently uses in-memory event publisher and user
        repository, but can be easily configured for production use.
    """
    # TODO: Add OAuth profile repository when implemented
    # For now, we'll need to create a mock or placeholder implementation
    # This is a temporary solution until the OAuth profile repository is implemented
    
    # Create a placeholder OAuth profile repository
    # In a real implementation, this would be a proper repository
    class PlaceholderOAuthProfileRepository:
        async def get_by_provider_and_user_id(self, provider, provider_user_id):
            return None
        
        async def get_by_user_id(self, user_id):
            return []
        
        async def create(self, oauth_profile):
            return oauth_profile
        
        async def update(self, oauth_profile):
            return oauth_profile
        
        async def delete(self, oauth_profile_id):
            pass
    
    oauth_profile_repository = PlaceholderOAuthProfileRepository()
    
    return OAuthAuthenticationService(
        user_repository=user_repository,
        oauth_profile_repository=oauth_profile_repository,
        event_publisher=event_publisher,
    )


def get_user_logout_service(
    token_service: ITokenService = Depends(get_token_service),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> IUserLogoutService:
    """Factory that returns clean user logout service.
    
    This factory creates the domain logout service with its dependencies,
    following dependency injection principles.
    
    Args:
        token_service: Token service dependency for token operations
        event_publisher: Event publisher dependency for domain events
        
    Returns:
        IUserLogoutService: Clean logout service
        
    Note:
        The logout service depends on abstractions (interfaces)
        rather than concrete implementations, following dependency
        inversion principle from SOLID.
    """
    return UserLogoutService(
        token_service=token_service,
        event_publisher=event_publisher,
    )


def get_password_change_service(
    user_repository: IUserRepository = Depends(get_user_repository),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> IPasswordChangeService:
    """Factory that returns clean password change service.
    
    This factory creates the domain password change service with its
    dependencies, following dependency injection principles.
    
    Args:
        user_repository: User repository dependency for data access
        event_publisher: Event publisher dependency for domain events
        
    Returns:
        IPasswordChangeService: Clean password change service
        
    Note:
        The password change service depends on abstractions (interfaces)
        rather than concrete implementations, following dependency
        inversion principle from SOLID.
    """
    return PasswordChangeService(
        user_repository=user_repository,
        event_publisher=event_publisher,
    )


def get_password_reset_rate_limiting_service() -> IRateLimitingService:
    """Factory that returns rate limiting service for password resets.
    
    This factory creates the rate limiting service to prevent abuse
    of password reset functionality.
    
    Returns:
        IRateLimitingService: Rate limiting service for password resets
        
    Note:
        The rate limiting service prevents brute force attacks on
        password reset functionality with configurable limits.
    """
    return RateLimitingService()


def get_password_reset_token_service(
    rate_limiting_service: IRateLimitingService = Depends(get_password_reset_rate_limiting_service),
) -> IPasswordResetTokenService:
    """Factory that returns enhanced password reset token service with rate limiting.
    
    This factory creates the enhanced token service for generating and validating
    password reset tokens with comprehensive security features including rate limiting.
    
    Args:
        rate_limiting_service: Rate limiting service for abuse prevention
        
    Returns:
        IPasswordResetTokenService: Enhanced token service for password resets
        
    Note:
        The enhanced token service includes:
        - Rate limiting per email address to prevent abuse
        - Unpredictable token format with mixed character sets
        - Cryptographically secure random generation
        - Constant-time validation to prevent timing attacks
        - Security metrics and monitoring capabilities
    """
    return PasswordResetTokenService(
        rate_limiting_service=rate_limiting_service
    )


def get_password_reset_email_service() -> IPasswordResetEmailService:
    """Factory that returns password reset email service.
    
    This factory creates the email service for sending password reset
    emails with internationalization support.
    
    Returns:
        IPasswordResetEmailService: Email service for password resets
        
    Note:
        The email service supports multiple languages and secure
        email delivery with proper template rendering.
    """
    return PasswordResetEmailService()


def get_password_reset_request_service(
    user_repository: IUserRepository = Depends(get_user_repository),
    rate_limiting_service: IRateLimitingService = Depends(get_password_reset_rate_limiting_service),
    token_service: IPasswordResetTokenService = Depends(get_password_reset_token_service),
    email_service: IPasswordResetEmailService = Depends(get_password_reset_email_service),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> PasswordResetRequestService:
    """Factory that returns password reset request service.
    
    This factory creates the domain service for handling password reset
    requests with all required dependencies.
    
    Args:
        user_repository: User repository dependency for data access
        rate_limiting_service: Rate limiting service for abuse prevention
        token_service: Token service for secure token generation
        email_service: Email service for sending reset emails
        event_publisher: Event publisher dependency for domain events
        
    Returns:
        PasswordResetRequestService: Service for password reset requests
        
    Note:
        This service coordinates all password reset request operations
        including validation, rate limiting, token generation, and email delivery.
    """
    return PasswordResetRequestService(
        user_repository=user_repository,
        rate_limiting_service=rate_limiting_service,
        token_service=token_service,
        email_service=email_service,
        event_publisher=event_publisher,
    )


def get_email_confirmation_token_service() -> IEmailConfirmationTokenService:
    return EmailConfirmationTokenService()


def get_email_confirmation_email_service() -> IEmailConfirmationEmailService:
    return EmailConfirmationEmailService()


def get_email_confirmation_request_service(
    user_repository: IUserRepository = Depends(get_user_repository),
    token_service: IEmailConfirmationTokenService = Depends(get_email_confirmation_token_service),
    email_service: IEmailConfirmationEmailService = Depends(get_email_confirmation_email_service),
) -> EmailConfirmationRequestService:
    return EmailConfirmationRequestService(
        user_repository=user_repository,
        token_service=token_service,
        email_service=email_service,
    )


def get_email_confirmation_service(
    user_repository: IUserRepository = Depends(get_user_repository),
    token_service: IEmailConfirmationTokenService = Depends(get_email_confirmation_token_service),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> EmailConfirmationService:
    return EmailConfirmationService(
        user_repository=user_repository,
        token_service=token_service,
        event_publisher=event_publisher,
    )


def get_password_reset_service(
    user_repository: IUserRepository = Depends(get_user_repository),
    token_service: IPasswordResetTokenService = Depends(get_password_reset_token_service),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> PasswordResetService:
    """Factory that returns password reset execution service.
    
    This factory creates the domain service for executing password resets
    using valid tokens.
    
    Args:
        user_repository: User repository dependency for data access
        token_service: Token service for validation and invalidation
        event_publisher: Event publisher dependency for domain events
        
    Returns:
        PasswordResetService: Service for password reset execution
        
    Note:
        This service handles the execution phase of password reset
        including token validation, password updates, and audit logging.
    """
    return PasswordResetService(
        user_repository=user_repository,
        token_service=token_service,
        event_publisher=event_publisher,
    )


# ---------------------------------------------------------------------------
# Convenience Aliases for Clean Architecture
# ---------------------------------------------------------------------------

# Infrastructure layer dependencies
CleanUserRepository = Annotated[IUserRepository, Depends(get_user_repository)]
CleanEventPublisher = Annotated[IEventPublisher, Depends(get_event_publisher)]
CleanTokenService = Annotated[ITokenService, Depends(get_token_service)]

# Domain service dependencies
CleanAuthService = Annotated[IUserAuthenticationService, Depends(get_user_authentication_service)]
CleanRegistrationService = Annotated[IUserRegistrationService, Depends(get_user_registration_service)]
CleanOAuthService = Annotated[IOAuthService, Depends(get_oauth_service)]
CleanPasswordChangeService = Annotated[IPasswordChangeService, Depends(get_password_change_service)]
CleanPasswordResetRequestService = Annotated[PasswordResetRequestService, Depends(get_password_reset_request_service)]
CleanPasswordResetService = Annotated[PasswordResetService, Depends(get_password_reset_service)]
CleanEmailConfirmationRequestService = Annotated[EmailConfirmationRequestService, Depends(get_email_confirmation_request_service)]
CleanEmailConfirmationService = Annotated[EmailConfirmationService, Depends(get_email_confirmation_service)]
