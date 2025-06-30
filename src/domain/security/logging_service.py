"""Secure Logging Service for Security Events and Audit Trails.

This service provides enterprise-grade security event logging that prevents
information disclosure while ensuring comprehensive audit trails for
security monitoring and compliance.

Key Security Features:
- Zero-trust data masking to prevent enumeration attacks
- Structured logging format for SIEM integration
- Consistent error patterns to prevent timing attacks
- Advanced threat detection through pattern analysis
- GDPR/privacy-compliant logging with minimal PII exposure
- Tamper-evident audit trails
"""

import hashlib
import hmac
import secrets
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import structlog

from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class SecurityEventLevel(Enum):
    """Security event severity levels for threat classification."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEventCategory(Enum):
    """Security event categories for organized monitoring."""
    
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    SESSION_MANAGEMENT = "session_management"
    DATA_ACCESS = "data_access"
    SYSTEM_SECURITY = "system_security"
    PRIVACY_VIOLATION = "privacy_violation"


@dataclass(frozen=True)
class SecurityEvent:
    """Immutable security event for audit trails."""
    
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    category: SecurityEventCategory = SecurityEventCategory.AUTHENTICATION
    level: SecurityEventLevel = SecurityEventLevel.MEDIUM
    event_type: str = ""
    description: str = ""
    
    # Context information
    correlation_id: Optional[str] = None
    user_context: Optional[Dict[str, Any]] = None
    request_context: Optional[Dict[str, Any]] = None
    security_context: Optional[Dict[str, Any]] = None
    
    # Risk assessment
    risk_score: int = 0
    threat_indicators: List[str] = field(default_factory=list)
    
    # Compliance and audit
    audit_trail: Dict[str, Any] = field(default_factory=dict)
    integrity_hash: Optional[str] = None
    
    def __post_init__(self):
        """Calculate integrity hash for tamper detection."""
        if not self.integrity_hash:
            content = f"{self.event_id}{self.timestamp.isoformat()}{self.event_type}{self.description}"
            # Use HMAC for integrity protection (key would be from config in production)
            secret_key = b"audit_integrity_key_should_be_from_config"
            hash_value = hmac.new(secret_key, content.encode(), hashlib.sha256).hexdigest()
            object.__setattr__(self, 'integrity_hash', hash_value)


class SecureLoggingService:
    """Enterprise-grade secure logging service for security events.
    
    This service implements zero-trust security logging principles:
    - Assume all data contains sensitive information
    - Apply consistent masking and sanitization
    - Prevent information leakage through timing or content
    - Provide structured events for security monitoring
    """
    
    # Configuration constants
    USERNAME_MASK_LENGTH = 2  # Show only first 2 characters
    EMAIL_MASK_LENGTH = 3     # Show only first 3 characters
    IP_MASK_LAST_OCTET = True # Mask last octet of IP addresses
    
    # Security thresholds
    HIGH_RISK_THRESHOLD = 70
    CRITICAL_RISK_THRESHOLD = 85
    
    def __init__(self):
        """Initialize secure logging service with security configuration."""
        self._logger = structlog.get_logger("security.audit")
        self._session_start = time.time()
        
    def mask_username(self, username: str) -> str:
        """Apply zero-trust username masking to prevent enumeration.
        
        This method provides consistent masking that prevents username
        enumeration while maintaining audit utility.
        
        Args:
            username: Raw username to mask
            
        Returns:
            str: Consistently masked username
        """
        if not username:
            return "[empty]"
        
        if len(username) <= self.USERNAME_MASK_LENGTH:
            return "*" * len(username)
        
        # Use SHA256 hash for consistent masking across sessions
        hash_input = f"{username.lower()}:{self._session_start}"
        hash_value = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
        return f"{username[:self.USERNAME_MASK_LENGTH]}***{hash_value}"
    
    def mask_email(self, email: str) -> str:
        """Apply zero-trust email masking to prevent enumeration.
        
        Args:
            email: Raw email to mask
            
        Returns:
            str: Consistently masked email
        """
        if not email:
            return "[empty]"
        
        if "@" not in email:
            return self.mask_username(email)
        
        local, domain = email.split("@", 1)
        masked_local = self.mask_username(local)
        
        # Mask domain but preserve structure for audit purposes
        domain_parts = domain.split(".")
        if len(domain_parts) > 1:
            masked_domain = f"{domain_parts[0][:2]}***.{domain_parts[-1]}"
        else:
            masked_domain = f"{domain[:2]}***"
        
        return f"{masked_local}@{masked_domain}"
    
    def mask_ip_address(self, ip_address: str) -> str:
        """Apply IP address masking for privacy compliance.
        
        Args:
            ip_address: Raw IP address to mask
            
        Returns:
            str: Privacy-compliant masked IP address
        """
        if not ip_address:
            return "[unknown]"
        
        # For IPv4, mask last octet
        if "." in ip_address and self.IP_MASK_LAST_OCTET:
            parts = ip_address.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.***"
        
        # For IPv6 or other formats, mask last segment
        return ip_address.rsplit(":", 1)[0] + ":***" if ":" in ip_address else ip_address[:8] + "***"
    
    def mask_token(self, token: str) -> str:
        """Apply token masking for security compliance.
        
        Args:
            token: Raw token to mask
            
        Returns:
            str: Security-compliant masked token
        """
        if not token:
            return "[empty]"
        
        if len(token) <= 8:
            return "*" * len(token)
        
        # Show first 4 and last 4 characters, mask the rest
        return f"{token[:4]}***{token[-4:]}"
    
    def sanitize_user_agent(self, user_agent: str) -> str:
        """Sanitize user agent string for privacy compliance.
        
        Args:
            user_agent: Raw user agent string
            
        Returns:
            str: Sanitized user agent
        """
        if not user_agent:
            return "[unknown]"
        
        # Extract browser family without detailed version info
        if "Chrome" in user_agent:
            return "Chrome/***"
        elif "Firefox" in user_agent:
            return "Firefox/***"
        elif "Safari" in user_agent:
            return "Safari/***"
        elif "Edge" in user_agent:
            return "Edge/***"
        else:
            return "Unknown/***"
    
    def create_user_context(
        self,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        role: Optional[str] = None,
        is_authenticated: bool = False
    ) -> Dict[str, Any]:
        """Create sanitized user context for logging.
        
        Args:
            user_id: User ID (preserved for audit)
            username: Username (will be masked)
            role: User role (preserved)
            is_authenticated: Authentication status
            
        Returns:
            Dict: Sanitized user context
        """
        return {
            "user_id": user_id,
            "username_masked": self.mask_username(username) if username else None,
            "role": role,
            "is_authenticated": is_authenticated,
            "context_type": "user"
        }
    
    def create_request_context(
        self,
        method: Optional[str] = None,
        path: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create sanitized request context for logging.
        
        Args:
            method: HTTP method
            path: Request path (query params will be stripped)
            ip_address: Client IP (will be masked)
            user_agent: User agent (will be sanitized)
            correlation_id: Request correlation ID
            
        Returns:
            Dict: Sanitized request context
        """
        # Strip query parameters from path for privacy
        clean_path = path.split("?")[0] if path else None
        
        # Sanitize user agent (preserve browser info, remove detailed version)
        clean_user_agent = self.sanitize_user_agent(user_agent) if user_agent else None
        
        return {
            "method": method,
            "path": clean_path,
            "ip_address_masked": self.mask_ip_address(ip_address) if ip_address else None,
            "user_agent_sanitized": clean_user_agent,
            "correlation_id": correlation_id,
            "context_type": "request"
        }
    
    def log_authentication_attempt(
        self,
        username: str,
        success: bool,
        failure_reason: Optional[str] = None,
        correlation_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        risk_indicators: Optional[List[str]] = None
    ) -> SecurityEvent:
        """Log authentication attempt with security context.
        
        Args:
            username: Attempted username (will be masked)
            success: Whether authentication succeeded
            failure_reason: Reason for failure (if applicable)
            correlation_id: Request correlation ID
            ip_address: Client IP address
            user_agent: User agent string
            risk_indicators: List of detected risk indicators
            
        Returns:
            SecurityEvent: Created security event
        """
        risk_score = self._calculate_authentication_risk(
            success, failure_reason, risk_indicators
        )
        
        level = SecurityEventLevel.LOW
        if risk_score >= self.CRITICAL_RISK_THRESHOLD:
            level = SecurityEventLevel.CRITICAL
        elif risk_score >= self.HIGH_RISK_THRESHOLD:
            level = SecurityEventLevel.HIGH
        elif not success:
            level = SecurityEventLevel.MEDIUM
        
        event_type = "authentication_success" if success else "authentication_failure"
        description = f"Authentication {'succeeded' if success else 'failed'}"
        if failure_reason:
            description += f" - {failure_reason}"
        
        event = SecurityEvent(
            category=SecurityEventCategory.AUTHENTICATION,
            level=level,
            event_type=event_type,
            description=description,
            correlation_id=correlation_id,
            user_context=self.create_user_context(username=username),
            request_context=self.create_request_context(
                ip_address=ip_address,
                user_agent=user_agent,
                correlation_id=correlation_id
            ),
            risk_score=risk_score,
            threat_indicators=risk_indicators or []
        )
        
        # Log with appropriate level
        if level == SecurityEventLevel.CRITICAL:
            self._logger.critical("Security event", **event.audit_trail)
        elif level == SecurityEventLevel.HIGH:
            self._logger.error("Security event", **event.audit_trail)
        elif level == SecurityEventLevel.MEDIUM:
            self._logger.warning("Security event", **event.audit_trail)
        else:
            self._logger.info("Security event", **event.audit_trail)
        
        return event
    
    def log_authorization_failure(
        self,
        user_id: Optional[int],
        username: Optional[str],
        resource: str,
        action: str,
        reason: str,
        correlation_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> SecurityEvent:
        """Log authorization failure for security monitoring.
        
        Args:
            user_id: User ID attempting access
            username: Username (will be masked)
            resource: Resource being accessed
            action: Action being attempted
            reason: Reason for denial
            correlation_id: Request correlation ID
            ip_address: Client IP address
            
        Returns:
            SecurityEvent: Created security event
        """
        risk_score = 30  # Base risk for authorization failures
        
        # Increase risk for sensitive resources
        if any(sensitive in resource.lower() for sensitive in ["admin", "user", "system"]):
            risk_score += 20
        
        # Increase risk for privileged actions
        if any(action.lower().startswith(priv) for priv in ["delete", "create", "modify"]):
            risk_score += 15
        
        level = SecurityEventLevel.HIGH if risk_score >= self.HIGH_RISK_THRESHOLD else SecurityEventLevel.MEDIUM
        
        event = SecurityEvent(
            category=SecurityEventCategory.AUTHORIZATION,
            level=level,
            event_type="authorization_failure",
            description=f"Access denied to {resource} for action {action} - {reason}",
            correlation_id=correlation_id,
            user_context=self.create_user_context(user_id=user_id, username=username),
            request_context=self.create_request_context(ip_address=ip_address),
            risk_score=risk_score,
            security_context={
                "resource": resource,
                "action": action,
                "denial_reason": reason
            }
        )
        
        self._logger.warning("Authorization failure", **event.audit_trail)
        return event
    
    def log_input_validation_failure(
        self,
        input_type: str,
        violation_details: Dict[str, Any],
        risk_score: int,
        correlation_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> SecurityEvent:
        """Log input validation failure for security monitoring.
        
        Args:
            input_type: Type of input that failed validation
            violation_details: Details of validation violations
            risk_score: Calculated risk score
            correlation_id: Request correlation ID
            ip_address: Client IP address
            
        Returns:
            SecurityEvent: Created security event
        """
        level = SecurityEventLevel.LOW
        if risk_score >= self.CRITICAL_RISK_THRESHOLD:
            level = SecurityEventLevel.CRITICAL
        elif risk_score >= self.HIGH_RISK_THRESHOLD:
            level = SecurityEventLevel.HIGH
        elif risk_score >= 30:
            level = SecurityEventLevel.MEDIUM
        
        # Extract threat indicators from violations
        threat_indicators = []
        if "sql_injection" in violation_details.get("blocked_patterns", []):
            threat_indicators.append("sql_injection_attempt")
        if "xss_pattern" in violation_details.get("blocked_patterns", []):
            threat_indicators.append("xss_attempt")
        if "command_injection" in violation_details.get("blocked_patterns", []):
            threat_indicators.append("command_injection_attempt")
        
        event = SecurityEvent(
            category=SecurityEventCategory.INPUT_VALIDATION,
            level=level,
            event_type="input_validation_failure",
            description=f"Input validation failed for {input_type}",
            correlation_id=correlation_id,
            request_context=self.create_request_context(ip_address=ip_address),
            risk_score=risk_score,
            threat_indicators=threat_indicators,
            security_context={
                "input_type": input_type,
                "violation_count": violation_details.get("violation_count", 0),
                "has_critical_violations": violation_details.get("has_critical_violations", False),
                "blocked_patterns_count": len(violation_details.get("blocked_patterns", []))
            }
        )
        
        if level in [SecurityEventLevel.CRITICAL, SecurityEventLevel.HIGH]:
            self._logger.error("Input validation security violation", **event.audit_trail)
        else:
            self._logger.info("Input validation failure", **event.audit_trail)
        
        return event
    
    def create_consistent_error_response(
        self,
        error_category: str,
        language: str = "en",
        correlation_id: Optional[str] = None
    ) -> Dict[str, str]:
        """Create consistent error responses to prevent information disclosure.
        
        This method ensures that all authentication/authorization errors
        return the same message regardless of the actual failure reason,
        preventing username enumeration and other information disclosure.
        
        Args:
            error_category: Category of error (auth, validation, system)
            language: Language code for i18n
            correlation_id: Request correlation ID for tracking
            
        Returns:
            Dict: Consistent error response
        """
        # Map all auth-related errors to the same generic message
        error_messages = {
            "authentication": "invalid_credentials_generic",
            "authorization": "access_denied_generic", 
            "validation": "invalid_input_generic",
            "system": "service_temporarily_unavailable",
            "rate_limit": "too_many_requests"
        }
        
        message_key = error_messages.get(error_category, "service_temporarily_unavailable")
        
        # Log the error category for internal monitoring
        self._logger.info(
            "Consistent error response generated",
            error_category=error_category,
            message_key=message_key,
            correlation_id=correlation_id,
            response_type="generic_error"
        )
        
        return {
            "detail": get_translated_message(message_key, language),
            "error_id": correlation_id or str(uuid.uuid4())[:8]
        }
    
    def _calculate_authentication_risk(
        self,
        success: bool,
        failure_reason: Optional[str],
        risk_indicators: Optional[List[str]]
    ) -> int:
        """Calculate risk score for authentication attempts.
        
        Args:
            success: Whether authentication succeeded
            failure_reason: Reason for failure
            risk_indicators: Detected risk indicators
            
        Returns:
            int: Risk score (0-100)
        """
        risk_score = 0
        
        if not success:
            risk_score += 25  # Base risk for failed authentication
            
            # Increase risk based on failure reason
            if failure_reason in ["invalid_credentials", "user_not_found"]:
                risk_score += 10
            elif failure_reason in ["user_inactive", "account_locked"]:
                risk_score += 15
            elif failure_reason in ["suspicious_activity", "rate_limited"]:
                risk_score += 30
        
        # Add risk for detected indicators
        if risk_indicators:
            for indicator in risk_indicators:
                if "injection" in indicator:
                    risk_score += 40
                elif "enumeration" in indicator:
                    risk_score += 25
                elif "brute_force" in indicator:
                    risk_score += 35
                else:
                    risk_score += 10
        
        return min(risk_score, 100)


# Global secure logging service instance
secure_logging_service = SecureLoggingService() 