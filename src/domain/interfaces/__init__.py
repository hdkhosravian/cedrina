"""Domain Interfaces for dependency inversion.

These interfaces define contracts that infrastructure and application
layers must implement, ensuring clean separation of concerns following
Domain-Driven Design principles.

Interface Organization by Bounded Context:
- Authentication: Core authentication operations (login, registration, logout)
- Token Management: JWT and session lifecycle management
- Password Management: Password reset and token operations
- OAuth: Third-party authentication integration
- Security: Encryption and protection mechanisms
- Infrastructure: Cross-cutting concerns (events, caching)

Key DDD Principles Applied:
- Single Responsibility: Each interface module has one clear purpose
- Bounded Context: Interfaces are organized by domain boundaries
- Dependency Inversion: Domain depends on abstractions, not concretions
- Interface Segregation: Clients depend only on interfaces they use
"""

# Repository interfaces
from .repositories import IUserRepository, IOAuthProfileRepository

# Authentication interfaces
from .authentication import (
    IUserAuthenticationService,
    IUserRegistrationService,
    IUserLogoutService,
    IPasswordChangeService,
    IPasswordResetTokenService,
    IPasswordResetEmailService,
    IOAuthService,
)
from .authentication.email_confirmation import (
    IEmailConfirmationTokenService,
    IEmailConfirmationEmailService,
)

# Token management interfaces
from .token_management import ITokenService, ISessionService

# Security interfaces
from .security import IPasswordEncryptionService, IRateLimitingService

# Infrastructure interfaces
from .infrastructure import IEventPublisher, ICacheService

__all__ = [
    # Repository interfaces
    "IUserRepository",
    "IOAuthProfileRepository",
    
    # Authentication interfaces
    "IUserAuthenticationService",
    "IUserRegistrationService", 
    "IUserLogoutService",
    "IPasswordChangeService",
    "IPasswordResetTokenService",
    "IPasswordResetEmailService",
    "IOAuthService",
    "IEmailConfirmationTokenService",
    "IEmailConfirmationEmailService",
    
    # Token management interfaces
    "ITokenService",
    "ISessionService",
    
    # Security interfaces
    "IPasswordEncryptionService",
    "IRateLimitingService",
    
    # Infrastructure interfaces
    "IEventPublisher",
    "ICacheService",
] 