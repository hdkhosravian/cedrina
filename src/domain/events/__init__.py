"""Domain Events for the authentication domain.

Domain events represent significant occurrences in the business domain
that other parts of the system may need to react to.
"""

from .password_reset_events import (
    PasswordResetRequestedEvent,
    PasswordResetCompletedEvent,
    PasswordResetFailedEvent,
    PasswordResetTokenExpiredEvent,
)
from .authentication_events import EmailConfirmedEvent

__all__ = [
    "PasswordResetRequestedEvent",
    "PasswordResetCompletedEvent", 
    "PasswordResetFailedEvent",
    "PasswordResetTokenExpiredEvent",
    "EmailConfirmedEvent",
]
