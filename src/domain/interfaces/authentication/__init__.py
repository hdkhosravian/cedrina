"""Authentication service interfaces for the authentication bounded context.

This module provides clean access to all authentication service interfaces
following Domain-Driven Design principles. These interfaces encapsulate the
business logic for user authentication, registration, logout, and password
management operations.

Key DDD Principles Applied:
- Single Responsibility: Each interface has one clear purpose
- Ubiquitous Language: Interface names reflect business domain concepts
- Dependency Inversion: Domain depends on abstractions, not concretions
- Bounded Context: All interfaces belong to the authentication domain
- Interface Segregation: Clients depend only on interfaces they use

Authentication Domain Services:
- User Authentication: Core authentication logic with security features
- User Registration: User account creation and validation
- User Logout: Session termination and token revocation
- Password Change: Secure password modification with validation
- Password Reset: Password reset workflows and token management
- OAuth Integration: Third-party authentication providers
- Token Management: JWT token lifecycle management
- Email Confirmation: Email confirmation workflow management
"""

# Core authentication interfaces
from .user_authentication import IUserAuthenticationService
from .user_registration import IUserRegistrationService
from .user_logout import IUserLogoutService
from .password_change import IPasswordChangeService

# Password management interfaces
from .password_reset import (
    IPasswordResetTokenService,
    IPasswordResetEmailService,
)

# OAuth interfaces
from .oauth import IOAuthService

# Token management interfaces
from .token_management import ITokenService

# Email confirmation interfaces
from .email_confirmation import (
    IEmailConfirmationService,
    IEmailConfirmationTokenService,
    IEmailConfirmationEmailService,
)

__all__ = [
    # Core authentication interfaces
    "IUserAuthenticationService",
    "IUserRegistrationService",
    "IUserLogoutService",
    "IPasswordChangeService",
    
    # Password management interfaces
    "IPasswordResetTokenService",
    "IPasswordResetEmailService",
    
    # OAuth interfaces
    "IOAuthService",
    
    # Token management interfaces
    "ITokenService",
    
    # Email confirmation interfaces
    "IEmailConfirmationService",
    "IEmailConfirmationTokenService",
    "IEmailConfirmationEmailService",
] 