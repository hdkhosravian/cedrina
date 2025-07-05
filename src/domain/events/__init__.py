"""Domain Events.

This module provides clean access to all domain events following DDD principles.
All events are immutable and represent significant business occurrences that
other parts of the system may need to react to.

Domain Events:
- Authentication Events: User registration, login, logout, OAuth
- Password Reset Events: Password reset requests and completions
- Email Confirmation Events: Email confirmation requests and completions
"""

# Authentication Events
from .authentication_events import (
    UserRegisteredEvent,
    UserLoggedInEvent,
    AuthenticationFailedEvent,
    UserLoggedOutEvent,
    OAuthAuthenticationSuccessEvent,
    OAuthAuthenticationFailedEvent,
)

# Password Reset Events
from .password_reset_events import (
    PasswordResetRequestedEvent,
    PasswordResetCompletedEvent,
    PasswordResetFailedEvent,
)

# Email Confirmation Events
from .email_confirmation_events import (
    EmailConfirmationRequestedEvent,
    EmailConfirmationCompletedEvent,
    EmailConfirmationFailedEvent,
)

__all__ = [
    # Authentication Events
    "UserRegisteredEvent",
    "UserLoggedInEvent",
    "AuthenticationFailedEvent",
    "UserLoggedOutEvent",
    "OAuthAuthenticationSuccessEvent",
    "OAuthAuthenticationFailedEvent",
    
    # Password Reset Events
    "PasswordResetRequestedEvent",
    "PasswordResetCompletedEvent",
    "PasswordResetFailedEvent",
    
    # Email Confirmation Events
    "EmailConfirmationRequestedEvent",
    "EmailConfirmationCompletedEvent",
    "EmailConfirmationFailedEvent",
] 