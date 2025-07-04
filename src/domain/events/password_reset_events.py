"""Password Reset Domain Events.

These events represent significant business occurrences in the password reset domain
that other parts of the system may need to react to (logging, monitoring, notifications).
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from pydantic import EmailStr


@dataclass(frozen=True)
class BaseDomainEvent:
    """Base class for all domain events.
    
    Attributes:
        occurred_at: When the event occurred
        user_id: ID of the user associated with the event
        correlation_id: Optional correlation ID for tracking
    """
    
    occurred_at: datetime
    user_id: int
    correlation_id: Optional[str]
    
    def __post_init__(self):
        """Ensure occurred_at is timezone-aware."""
        if not self.occurred_at.tzinfo:
            # Convert to UTC if timezone-naive
            object.__setattr__(self, 'occurred_at', 
                             self.occurred_at.replace(tzinfo=timezone.utc))


@dataclass(frozen=True)
class PasswordResetRequestedEvent(BaseDomainEvent):
    """Event emitted when a password reset is requested.
    
    This event is useful for:
    - Audit logging
    - Security monitoring
    - Rate limiting analytics
    - Email delivery tracking
    
    Attributes:
        email: Email address the reset was requested for
        token_expires_at: When the reset token expires
        language: Language used for the request
        user_agent: Optional user agent string
        ip_address: Optional IP address of requester
    """
    
    email: EmailStr
    token_expires_at: datetime
    language: str = "en"
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None


@dataclass(frozen=True)
class PasswordResetCompletedEvent(BaseDomainEvent):
    """Event emitted when a password reset is successfully completed.
    
    This event is useful for:
    - Audit logging
    - Security notifications
    - Analytics
    - Triggering additional security measures
    
    Attributes:
        email: Email address of the user
        reset_method: Method used for reset (e.g., "token")
        user_agent: Optional user agent string
        ip_address: Optional IP address of requester
    """
    
    email: EmailStr
    reset_method: str = "token"
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None


@dataclass(frozen=True)
class PasswordResetFailedEvent(BaseDomainEvent):
    """Event emitted when a password reset attempt fails.
    
    This event is useful for:
    - Security monitoring
    - Fraud detection
    - Rate limiting adjustments
    - Alert generation
    
    Attributes:
        email: Email address of the attempted reset
        failure_reason: Reason for failure
        token_used: Masked token that was used (if any)
        user_agent: Optional user agent string
        ip_address: Optional IP address of requester
    """
    
    email: EmailStr
    failure_reason: str
    token_used: Optional[str] = None
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None


@dataclass(frozen=True)
class PasswordResetTokenExpiredEvent(BaseDomainEvent):
    """Event emitted when a password reset token expires.
    
    This event is useful for:
    - Cleanup operations
    - Analytics on token usage patterns
    - Security monitoring
    
    Attributes:
        email: Email address associated with expired token
        token_created_at: When the token was originally created
        expired_at: When the token expired
    """
    
    email: EmailStr
    token_created_at: datetime
    expired_at: datetime 