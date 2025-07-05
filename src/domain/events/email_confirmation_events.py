"""Email Confirmation Domain Events.

These events represent significant business occurrences in the email confirmation domain
that other parts of the system may need to react to (logging, monitoring, notifications).
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from .password_reset_events import BaseDomainEvent


@dataclass(frozen=True)
class EmailConfirmationRequestedEvent(BaseDomainEvent):
    """Event published when an email confirmation is requested.
    
    This event signals that a user has requested an email confirmation
    and can trigger email sending, analytics, and audit logging.
    
    Attributes:
        email: Email address of the user requesting confirmation
        confirmation_method: Method used for confirmation (email, resend)
        user_agent: Browser/client user agent
        ip_address: Client IP address
    """
    
    email: str
    confirmation_method: str = "email"
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    
    @classmethod
    def create(
        cls,
        user_id: int,
        email: str,
        confirmation_method: str = "email",
        correlation_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> 'EmailConfirmationRequestedEvent':
        """Create email confirmation requested event with current timestamp.
        
        Args:
            user_id: ID of the user requesting confirmation
            email: Email address of the user
            confirmation_method: Method used for confirmation
            correlation_id: Optional correlation ID for tracking
            user_agent: Browser/client user agent
            ip_address: Client IP address
            
        Returns:
            EmailConfirmationRequestedEvent: New event instance
        """
        return cls(
            occurred_at=datetime.now(timezone.utc),
            user_id=user_id,
            correlation_id=correlation_id,
            email=email,
            confirmation_method=confirmation_method,
            user_agent=user_agent,
            ip_address=ip_address,
        )


@dataclass(frozen=True)
class EmailConfirmationCompletedEvent(BaseDomainEvent):
    """Event published when an email confirmation is completed successfully.
    
    This event signals that a user has successfully confirmed their email
    and can trigger account activation, welcome emails, and audit logging.
    
    Attributes:
        email: Email address of the confirmed user
        confirmation_method: Method used for confirmation (token)
        user_agent: Browser/client user agent
        ip_address: Client IP address
    """
    
    email: str
    confirmation_method: str = "token"
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    
    @classmethod
    def create(
        cls,
        user_id: int,
        email: str,
        confirmation_method: str = "token",
        correlation_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> 'EmailConfirmationCompletedEvent':
        """Create email confirmation completed event with current timestamp.
        
        Args:
            user_id: ID of the confirmed user
            email: Email address of the confirmed user
            confirmation_method: Method used for confirmation
            correlation_id: Optional correlation ID for tracking
            user_agent: Browser/client user agent
            ip_address: Client IP address
            
        Returns:
            EmailConfirmationCompletedEvent: New event instance
        """
        return cls(
            occurred_at=datetime.now(timezone.utc),
            user_id=user_id,
            correlation_id=correlation_id,
            email=email,
            confirmation_method=confirmation_method,
            user_agent=user_agent,
            ip_address=ip_address,
        )


@dataclass(frozen=True)
class EmailConfirmationFailedEvent(BaseDomainEvent):
    """Event published when an email confirmation fails.
    
    This event signals that an email confirmation attempt has failed
    and can trigger security monitoring, fraud detection, and audit logging.
    
    Attributes:
        email: Email address of the failed confirmation attempt
        failure_reason: Reason for the failure (invalid_token, user_not_found, etc.)
        confirmation_method: Method used for confirmation attempt
        user_agent: Browser/client user agent
        ip_address: Client IP address
    """
    
    email: str
    failure_reason: str
    confirmation_method: str = "token"
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    
    @classmethod
    def create(
        cls,
        user_id: Optional[int],
        email: str,
        failure_reason: str,
        confirmation_method: str = "token",
        correlation_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> 'EmailConfirmationFailedEvent':
        """Create email confirmation failed event with current timestamp.
        
        Args:
            user_id: ID of the user (if known)
            email: Email address of the failed confirmation attempt
            failure_reason: Reason for the failure
            confirmation_method: Method used for confirmation attempt
            correlation_id: Optional correlation ID for tracking
            user_agent: Browser/client user agent
            ip_address: Client IP address
            
        Returns:
            EmailConfirmationFailedEvent: New event instance
        """
        return cls(
            occurred_at=datetime.now(timezone.utc),
            user_id=user_id,
            correlation_id=correlation_id,
            email=email,
            failure_reason=failure_reason,
            confirmation_method=confirmation_method,
            user_agent=user_agent,
            ip_address=ip_address,
        ) 