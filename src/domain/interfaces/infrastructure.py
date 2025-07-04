"""Infrastructure service interfaces for cross-cutting concerns.

This module defines the infrastructure service interfaces following Domain-Driven
Design principles. These interfaces encapsulate the business logic for caching,
event publishing, and other cross-cutting infrastructure concerns.

Key DDD Principles Applied:
- Single Responsibility: Each interface has one clear purpose
- Ubiquitous Language: Interface names reflect business domain concepts
- Dependency Inversion: Domain depends on abstractions, not concretions
- Bounded Context: All interfaces belong to the infrastructure domain
- Interface Segregation: Clients depend only on interfaces they use

Infrastructure Domain Services:
- Event Publisher: Domain event publishing and distribution
- Cache Service: Generic caching operations and management
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from src.domain.events.password_reset_events import BaseDomainEvent


class IEventPublisher(ABC):
    """Interface for domain event publishing and distribution.
    
    This service provides a mechanism for publishing events that occur within
    the domain (e.g., `UserRegistered`, `PasswordChanged`). It decouples the part
    of the domain that raises the event from the listeners that handle it,
    enabling a clean, event-driven architecture.
    
    DDD Principles:
    - Single Responsibility: Handles only event publishing operations
    - Domain Events: Publishes domain events for loose coupling
    - Ubiquitous Language: Method names reflect event concepts
    - Dependency Inversion: Abstracts event infrastructure from domain
    """

    @abstractmethod
    async def publish(self, event: BaseDomainEvent) -> None:
        """Publishes a single domain event.

        Args:
            event: The `BaseDomainEvent` to be published to all listeners.
        """
        raise NotImplementedError

    @abstractmethod
    async def publish_many(self, events: List[BaseDomainEvent]) -> None:
        """Publishes a list of domain events.

        This can be used to publish multiple events that occur as part of a
        single transaction or use case.

        Args:
            events: A list of `BaseDomainEvent` objects to be published.
        """
        raise NotImplementedError


class ICacheService(ABC):
    """Interface for generic caching operations and management.
    
    This provides a simple, abstract contract for cache operations (get, set,
    delete, exists). It decouples the application from any specific cache
    implementation (e.g., Redis, in-memory), allowing the caching backend to be
    swapped without affecting the domain or application logic.
    
    DDD Principles:
    - Single Responsibility: Handles only caching operations
    - Ubiquitous Language: Method names reflect caching concepts
    - Dependency Inversion: Abstracts cache infrastructure from domain
    - Interface Segregation: Provides minimal, focused caching contract
    """

    @abstractmethod
    async def get(self, key: str) -> Optional[str]:
        """Retrieves a value from the cache by its key.

        Args:
            key: The key of the item to retrieve.

        Returns:
            The cached value as a string, or `None` if the key is not found.
        """
        raise NotImplementedError

    @abstractmethod
    async def set(self, key: str, value: str, expire_seconds: Optional[int] = None) -> None:
        """Stores a key-value pair in the cache.

        Args:
            key: The key under which to store the value.
            value: The string value to store.
            expire_seconds: The time-to-live for the cache entry, in seconds.
                If `None`, the cache's default expiration may be used.
        """
        raise NotImplementedError

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Deletes a key-value pair from the cache.

        Args:
            key: The key of the item to delete.
        """
        raise NotImplementedError

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Checks if a key exists in the cache.

        Args:
            key: The key to check for.

        Returns:
            `True` if the key exists, `False` otherwise.
        """
        raise NotImplementedError 