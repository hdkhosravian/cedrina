"""Structured Security Events for Comprehensive Audit Trails.

This module provides a structured event system for security monitoring,
compliance reporting, and threat detection. All events are designed to
be SIEM-compatible and follow security logging best practices.

Key Features:
- SIEM-compatible structured format
- Privacy-compliant data handling
- Tamper-evident event integrity
- Risk-based event classification
- Compliance audit trail support
"""

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import structlog

from src.domain.security.logging_service import SecurityEventCategory, SecurityEventLevel


@dataclass(frozen=True)
class SecurityMetadata:
    """Security metadata for events."""
    
    classification: str = "internal"
    retention_period_days: int = 365
    requires_encryption: bool = True
    pii_categories: List[str] = field(default_factory=list)
    compliance_tags: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ThreatIntelligence:
    """Threat intelligence data for security events."""
    
    threat_type: Optional[str] = None
    severity_score: int = 0  # 0-100
    attack_patterns: List[str] = field(default_factory=list)
    indicators_of_compromise: List[str] = field(default_factory=list)
    mitigation_actions: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class StructuredSecurityEvent:
    """Comprehensive structured security event for audit and monitoring.
    
    This event format is designed for:
    - SIEM integration and analysis
    - Compliance audit trails
    - Threat detection and response
    - Privacy-compliant logging
    """
    
    # Event identification
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_version: str = "1.0"
    
    # Event classification
    category: SecurityEventCategory = SecurityEventCategory.AUTHENTICATION
    subcategory: str = ""
    event_type: str = ""
    severity: SecurityEventLevel = SecurityEventLevel.MEDIUM
    
    # Event description
    title: str = ""
    description: str = ""
    outcome: str = ""  # success, failure, error, unknown
    
    # Source information
    source_system: str = "cedrina-auth"
    source_component: str = ""
    source_function: str = ""
    
    # Actor information (privacy-compliant)
    actor_id: Optional[str] = None
    actor_type: str = "user"  # user, system, service, anonymous
    actor_session_id: Optional[str] = None
    
    # Target information
    target_resource: Optional[str] = None
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    
    # Request context
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None
    client_ip_masked: Optional[str] = None
    user_agent_sanitized: Optional[str] = None
    request_method: Optional[str] = None
    request_path: Optional[str] = None
    
    # Security context
    risk_score: int = 0  # 0-100
    confidence_level: int = 100  # How confident we are in the event accuracy
    false_positive_likelihood: int = 0  # 0-100
    
    # Additional data
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    
    # Security metadata
    security_metadata: SecurityMetadata = field(default_factory=SecurityMetadata)
    threat_intel: Optional[ThreatIntelligence] = None
    
    # Event integrity
    checksum: Optional[str] = None
    
    def __post_init__(self):
        """Calculate event checksum for integrity verification."""
        if not self.checksum:
            # Create content hash for integrity
            content = {
                "event_id": self.event_id,
                "timestamp": self.timestamp.isoformat(),
                "category": self.category.value,
                "event_type": self.event_type,
                "description": self.description,
                "actor_id": self.actor_id,
                "request_id": self.request_id
            }
            content_str = json.dumps(content, sort_keys=True)
            checksum = hashlib.sha256(content_str.encode()).hexdigest()
            object.__setattr__(self, 'checksum', checksum)
    
    def to_siem_format(self) -> Dict[str, Any]:
        """Convert event to SIEM-compatible format.
        
        Returns:
            Dict: SIEM-compatible event data
        """
        siem_event = {
            # Common Event Format (CEF) compatible fields
            "timestamp": self.timestamp.isoformat(),
            "event_id": self.event_id,
            "version": self.event_version,
            "device_vendor": "Cedrina",
            "device_product": "Authentication Service",
            "device_version": "1.0",
            "signature_id": f"{self.category.value}_{self.event_type}",
            "name": self.title,
            "severity": self._severity_to_numeric(),
            
            # Event details
            "category": self.category.value,
            "subcategory": self.subcategory,
            "event_type": self.event_type,
            "outcome": self.outcome,
            "message": self.description,
            
            # Source
            "source_system": self.source_system,
            "source_component": self.source_component,
            
            # Actor (privacy-compliant)
            "actor_id": self.actor_id,
            "actor_type": self.actor_type,
            "session_id": self.actor_session_id,
            
            # Target
            "target_resource": self.target_resource,
            "target_type": self.target_type,
            "target_id": self.target_id,
            
            # Request context
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "client_ip": self.client_ip_masked,
            "user_agent": self.user_agent_sanitized,
            "http_method": self.request_method,
            "request_path": self.request_path,
            
            # Risk assessment
            "risk_score": self.risk_score,
            "confidence": self.confidence_level,
            
            # Additional context
            "tags": self.tags,
            "custom_fields": self.custom_fields,
            
            # Integrity
            "checksum": self.checksum
        }
        
        # Add threat intelligence if present
        if self.threat_intel:
            siem_event.update({
                "threat_type": self.threat_intel.threat_type,
                "threat_severity": self.threat_intel.severity_score,
                "attack_patterns": self.threat_intel.attack_patterns,
                "iocs": self.threat_intel.indicators_of_compromise
            })
        
        return siem_event
    
    def to_audit_format(self) -> Dict[str, Any]:
        """Convert event to compliance audit format.
        
        Returns:
            Dict: Audit-compatible event data
        """
        audit_event = {
            "audit_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_category": self.category.value,
            "event_type": self.event_type,
            "event_outcome": self.outcome,
            "event_description": self.description,
            
            # Subject (actor)
            "subject_id": self.actor_id,
            "subject_type": self.actor_type,
            
            # Object (target)
            "object_resource": self.target_resource,
            "object_type": self.target_type,
            "object_id": self.target_id,
            
            # Context
            "session_id": self.actor_session_id,
            "request_id": self.request_id,
            "source_ip": self.client_ip_masked,
            
            # Compliance metadata
            "retention_required": True,
            "retention_period_days": self.security_metadata.retention_period_days,
            "classification": self.security_metadata.classification,
            "compliance_tags": self.security_metadata.compliance_tags,
            
            # Integrity
            "integrity_hash": self.checksum
        }
        
        return audit_event
    
    def _severity_to_numeric(self) -> int:
        """Convert severity level to numeric value for SIEM systems."""
        severity_mapping = {
            SecurityEventLevel.LOW: 1,
            SecurityEventLevel.MEDIUM: 5,
            SecurityEventLevel.HIGH: 8,
            SecurityEventLevel.CRITICAL: 10
        }
        return severity_mapping.get(self.severity, 5)


class StructuredEventBuilder:
    """Builder for creating structured security events.
    
    This builder provides a fluent interface for creating comprehensive
    security events with proper validation and defaults.
    """
    
    def __init__(self):
        """Initialize event builder with defaults."""
        self._event_data = {}
        self._custom_fields = {}
        self._tags = []
    
    def authentication_event(
        self,
        event_type: str,
        outcome: str,
        username_masked: Optional[str] = None,
        failure_reason: Optional[str] = None
    ) -> 'StructuredEventBuilder':
        """Configure as authentication event.
        
        Args:
            event_type: Type of authentication event
            outcome: Event outcome (success/failure)
            username_masked: Masked username
            failure_reason: Reason for failure
            
        Returns:
            StructuredEventBuilder: Self for chaining
        """
        self._event_data.update({
            "category": SecurityEventCategory.AUTHENTICATION,
            "subcategory": "user_authentication",
            "event_type": event_type,
            "outcome": outcome,
            "source_component": "authentication_service"
        })
        
        if username_masked:
            self._event_data["actor_id"] = username_masked
            self._event_data["actor_type"] = "user"
        
        if failure_reason:
            self._custom_fields["failure_reason"] = failure_reason
        
        return self
    
    def authorization_event(
        self,
        event_type: str,
        outcome: str,
        resource: str,
        action: str,
        user_id: Optional[str] = None
    ) -> 'StructuredEventBuilder':
        """Configure as authorization event.
        
        Args:
            event_type: Type of authorization event
            outcome: Event outcome
            resource: Target resource
            action: Attempted action
            user_id: User ID
            
        Returns:
            StructuredEventBuilder: Self for chaining
        """
        self._event_data.update({
            "category": SecurityEventCategory.AUTHORIZATION,
            "subcategory": "access_control",
            "event_type": event_type,
            "outcome": outcome,
            "target_resource": resource,
            "target_type": "resource",
            "source_component": "authorization_service"
        })
        
        if user_id:
            self._event_data["actor_id"] = user_id
            self._event_data["actor_type"] = "user"
        
        self._custom_fields["attempted_action"] = action
        
        return self
    
    def input_validation_event(
        self,
        input_type: str,
        validation_outcome: str,
        risk_score: int,
        violations: List[str]
    ) -> 'StructuredEventBuilder':
        """Configure as input validation event.
        
        Args:
            input_type: Type of input validated
            validation_outcome: Outcome of validation
            risk_score: Calculated risk score
            violations: List of validation violations
            
        Returns:
            StructuredEventBuilder: Self for chaining
        """
        self._event_data.update({
            "category": SecurityEventCategory.INPUT_VALIDATION,
            "subcategory": "data_validation",
            "event_type": "input_validation",
            "outcome": validation_outcome,
            "risk_score": risk_score,
            "source_component": "input_sanitizer"
        })
        
        self._custom_fields.update({
            "input_type": input_type,
            "violations": violations,
            "violation_count": len(violations)
        })
        
        return self
    
    def with_severity(self, severity: SecurityEventLevel) -> 'StructuredEventBuilder':
        """Set event severity.
        
        Args:
            severity: Event severity level
            
        Returns:
            StructuredEventBuilder: Self for chaining
        """
        self._event_data["severity"] = severity
        return self
    
    def with_request_context(
        self,
        correlation_id: Optional[str] = None,
        request_id: Optional[str] = None,
        client_ip_masked: Optional[str] = None,
        user_agent_sanitized: Optional[str] = None,
        method: Optional[str] = None,
        path: Optional[str] = None
    ) -> 'StructuredEventBuilder':
        """Add request context.
        
        Args:
            correlation_id: Request correlation ID
            request_id: Request ID
            client_ip_masked: Masked client IP
            user_agent_sanitized: Sanitized user agent
            method: HTTP method
            path: Request path
            
        Returns:
            StructuredEventBuilder: Self for chaining
        """
        context = {
            "correlation_id": correlation_id,
            "request_id": request_id,
            "client_ip_masked": client_ip_masked,
            "user_agent_sanitized": user_agent_sanitized,
            "request_method": method,
            "request_path": path
        }
        
        # Filter out None values
        self._event_data.update({k: v for k, v in context.items() if v is not None})
        
        return self
    
    def with_threat_intelligence(
        self,
        threat_type: str,
        severity_score: int,
        attack_patterns: Optional[List[str]] = None,
        iocs: Optional[List[str]] = None
    ) -> 'StructuredEventBuilder':
        """Add threat intelligence data.
        
        Args:
            threat_type: Type of threat detected
            severity_score: Threat severity (0-100)
            attack_patterns: Detected attack patterns
            iocs: Indicators of compromise
            
        Returns:
            StructuredEventBuilder: Self for chaining
        """
        self._event_data["threat_intel"] = ThreatIntelligence(
            threat_type=threat_type,
            severity_score=severity_score,
            attack_patterns=attack_patterns or [],
            indicators_of_compromise=iocs or []
        )
        
        return self
    
    def with_custom_field(self, key: str, value: Any) -> 'StructuredEventBuilder':
        """Add custom field to event.
        
        Args:
            key: Field key
            value: Field value
            
        Returns:
            StructuredEventBuilder: Self for chaining
        """
        self._custom_fields[key] = value
        return self
    
    def with_tag(self, tag: str) -> 'StructuredEventBuilder':
        """Add tag to event.
        
        Args:
            tag: Tag to add
            
        Returns:
            StructuredEventBuilder: Self for chaining
        """
        self._tags.append(tag)
        return self
    
    def build(self) -> StructuredSecurityEvent:
        """Build the structured security event.
        
        Returns:
            StructuredSecurityEvent: Completed event
        """
        # Set custom fields and tags
        self._event_data["custom_fields"] = self._custom_fields
        self._event_data["tags"] = self._tags
        
        # Create event
        return StructuredSecurityEvent(**self._event_data)


class SecurityEventLogger:
    """Logger for structured security events with multiple output formats."""
    
    def __init__(self):
        """Initialize security event logger."""
        self._logger = structlog.get_logger("security.structured")
        self._audit_logger = structlog.get_logger("audit.compliance")
        self._siem_logger = structlog.get_logger("siem.events")
    
    def log_event(self, event: StructuredSecurityEvent) -> None:
        """Log structured security event to all configured outputs.
        
        Args:
            event: Structured security event to log
        """
        # Log to general security log
        self._logger.info(
            "Structured security event",
            **asdict(event)
        )
        
        # Log to audit trail
        self._audit_logger.info(
            "Audit event",
            **event.to_audit_format()
        )
        
        # Log to SIEM format
        self._siem_logger.info(
            "SIEM event",
            **event.to_siem_format()
        )
    
    def log_authentication_success(
        self,
        username_masked: str,
        correlation_id: str,
        client_ip_masked: str,
        user_agent_sanitized: str
    ) -> None:
        """Log successful authentication event.
        
        Args:
            username_masked: Masked username
            correlation_id: Request correlation ID
            client_ip_masked: Masked client IP
            user_agent_sanitized: Sanitized user agent
        """
        event = (StructuredEventBuilder()
                .authentication_event("login_success", "success", username_masked)
                .with_severity(SecurityEventLevel.LOW)
                .with_request_context(
                    correlation_id=correlation_id,
                    client_ip_masked=client_ip_masked,
                    user_agent_sanitized=user_agent_sanitized
                )
                .with_tag("authentication")
                .with_tag("success")
                .build())
        
        self.log_event(event)
    
    def log_authentication_failure(
        self,
        username_masked: str,
        failure_reason: str,
        correlation_id: str,
        client_ip_masked: str,
        risk_score: int
    ) -> None:
        """Log failed authentication event.
        
        Args:
            username_masked: Masked username
            failure_reason: Reason for failure
            correlation_id: Request correlation ID
            client_ip_masked: Masked client IP
            risk_score: Calculated risk score
        """
        # Determine severity based on risk score
        if risk_score >= 80:
            severity = SecurityEventLevel.CRITICAL
        elif risk_score >= 60:
            severity = SecurityEventLevel.HIGH
        else:
            severity = SecurityEventLevel.MEDIUM
        
        event = (StructuredEventBuilder()
                .authentication_event("login_failure", "failure", username_masked, failure_reason)
                .with_severity(severity)
                .with_request_context(
                    correlation_id=correlation_id,
                    client_ip_masked=client_ip_masked
                )
                .with_custom_field("risk_score", risk_score)
                .with_tag("authentication")
                .with_tag("failure")
                .build())
        
        self.log_event(event)


# Global structured event logger instance
security_event_logger = SecurityEventLogger() 