"""Domain Services for the Authentication Bounded Context.

This module provides clean access to all domain services following DDD principles.
All services implement the single responsibility principle and use dependency injection
through interfaces for loose coupling and testability.

Authentication Domain Services:
- User Authentication: Core authentication logic with security features
- User Registration: User account creation and validation
- User Logout: Session termination and token revocation
- Password Management: Password change and reset operations
- OAuth Integration: Third-party authentication providers
- Token Management: JWT token lifecycle management

Security Domain Services:
- Password Policy: Business rules for password strength and validation
- Policy Management: Authorization policies with ABAC support and audit trails

Email and Reset Services:
- Email Service: Template rendering and email delivery
- Password Reset: Request and completion workflows
"""

# Authentication Services (DDD-compliant implementations)
from .authentication.user_authentication_service import UserAuthenticationService
from .authentication.user_authentication_security_service import UserAuthenticationSecurityService
from .authentication.user_registration_service import UserRegistrationService
from .authentication.user_logout_service import UserLogoutService
from .authentication.password_change_service import PasswordChangeService
from .authentication.oauth_service import OAuthAuthenticationService

# Security Services
from .security.password_policy import PasswordPolicyValidator
from .security.policy import PolicyService

# Password Reset Services
from .password_reset.password_reset_request_service import PasswordResetRequestService
from .password_reset.password_reset_service import PasswordResetService

# Email Services
from .email.email_service import EmailService

__all__ = [
    # Authentication Domain Services
    "UserAuthenticationService",
    "UserAuthenticationSecurityService", 
    "UserRegistrationService",
    "UserLogoutService",
    "PasswordChangeService",
    "OAuthAuthenticationService",
    
    # Security Domain Services
    "PasswordPolicyValidator",
    "PolicyService",
    
    # Password Reset Services
    "PasswordResetRequestService",
    "PasswordResetService",
    
    # Email Services
    "EmailService",
]
