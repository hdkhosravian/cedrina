"""Clean Architecture Dependencies for Authentication.

This module provides dependency injection for clean authentication services
following Domain-Driven Design principles and dependency inversion.
"""

from typing import Annotated

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.interfaces.repositories import IUserRepository
from src.domain.interfaces.services import (
    IEventPublisher,
    ITokenService,
    IUserAuthenticationService,
    IUserRegistrationService,
)
from src.domain.services.auth.token import TokenService as LegacyTokenService
from src.domain.services.authentication.user_authentication_service import (
    UserAuthenticationService,
)
from src.domain.services.authentication.user_registration_service import (
    UserRegistrationService,
)
from src.infrastructure.database.async_db import get_async_db
from src.infrastructure.redis import get_redis
from src.infrastructure.repositories.user_repository import UserRepository
from src.infrastructure.services.event_publisher import InMemoryEventPublisher
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
    
    Args:
        db: Database session dependency
        
    Returns:
        IUserRepository: Clean user repository implementation
    """
    return UserRepository(db)


def get_event_publisher() -> IEventPublisher:
    """Factory that returns event publisher implementation.
    
    Returns:
        IEventPublisher: Event publisher for domain events
        
    Note:
        In production, this could be configured to return:
        - Redis pub/sub implementation
        - RabbitMQ implementation
        - Kafka implementation
        Currently returns in-memory implementation for development
    """
    return InMemoryEventPublisher()


def get_token_service(
    db: AsyncDB,
    redis: RedisClient,
) -> ITokenService:
    """Factory that returns clean token service implementation.
    
    This adapter wraps the existing token service to work with clean architecture
    while maintaining compatibility with existing infrastructure.
    
    Args:
        db: Database session dependency
        redis: Redis client dependency
        
    Returns:
        ITokenService: Clean token service implementation
    """
    # Create legacy token service
    legacy_service = LegacyTokenService(db, redis)
    
    # Wrap with adapter for clean architecture
    return TokenServiceAdapter(legacy_service)


# ---------------------------------------------------------------------------
# Domain Service Dependencies
# ---------------------------------------------------------------------------


def get_user_authentication_service(
    user_repository: IUserRepository = Depends(get_user_repository),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> IUserAuthenticationService:
    """Factory that returns clean user authentication service.
    
    Args:
        user_repository: User repository dependency
        event_publisher: Event publisher dependency
        
    Returns:
        IUserAuthenticationService: Clean authentication service
    """
    return UserAuthenticationService(
        user_repository=user_repository,
        event_publisher=event_publisher,
    )


def get_user_registration_service(
    user_repository: IUserRepository = Depends(get_user_repository),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> IUserRegistrationService:
    """Factory that returns clean user registration service.
    
    Args:
        user_repository: User repository dependency
        event_publisher: Event publisher dependency
        
    Returns:
        IUserRegistrationService: Clean registration service
    """
    return UserRegistrationService(
        user_repository=user_repository,
        event_publisher=event_publisher,
    )


# ---------------------------------------------------------------------------
# Convenience Aliases for Clean Architecture
# ---------------------------------------------------------------------------

CleanUserRepository = Annotated[IUserRepository, Depends(get_user_repository)]
CleanEventPublisher = Annotated[IEventPublisher, Depends(get_event_publisher)]
CleanTokenService = Annotated[ITokenService, Depends(get_token_service)]
CleanAuthService = Annotated[IUserAuthenticationService, Depends(get_user_authentication_service)]
CleanRegistrationService = Annotated[IUserRegistrationService, Depends(get_user_registration_service)] 