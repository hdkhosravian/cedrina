"""Secure User Agent value object with advanced sanitization and security controls.

This module provides a secure User Agent value object that prevents log injection,
XSS attacks, and other security vulnerabilities related to user agent string handling.
"""

from dataclasses import dataclass
from typing import ClassVar, Optional

import structlog

from src.domain.validation.input_sanitizer import (
    input_sanitizer_service,
    ValidationResult,
    ValidationSeverity
)

logger = structlog.get_logger(__name__)


class UserAgentSanitizationError(ValueError):
    """Exception raised when user agent sanitization fails with security details."""
    
    def __init__(self, message: str, validation_result: ValidationResult):
        super().__init__(message)
        self.validation_result = validation_result
        self.risk_score = validation_result.risk_score
        self.violations = validation_result.violations
        self.blocked_patterns = validation_result.blocked_patterns


@dataclass(frozen=True)
class SecureUserAgent:
    """Secure user agent value object with comprehensive sanitization and security controls.
    
    This value object provides enterprise-grade user agent sanitization including:
    - Control character removal (prevents log injection attacks)
    - XSS pattern detection and neutralization
    - Length limiting to prevent DoS attacks
    - Encoding normalization and Unicode safety
    - Suspicious pattern detection and risk assessment
    - Comprehensive audit logging of security violations
    
    Security Features:
    - Zero-trust input sanitization approach
    - OWASP-compliant security controls for log injection prevention
    - Layered defense against multiple attack vectors
    - Comprehensive audit trails for security monitoring
    - Risk-based validation with severity assessment
    
    Business Rules:
    - Maximum length: 500 characters (configurable)
    - Control characters removed automatically
    - HTML entities encoded for safety
    - Unicode normalized to prevent encoding attacks
    - Suspicious patterns detected and logged
    """
    
    value: str
    _validation_result: ValidationResult
    
    # Configuration constants
    DEFAULT_MAX_LENGTH: ClassVar[int] = 500
    FALLBACK_VALUE: ClassVar[str] = "unknown"
    
    def __post_init__(self):
        """Sanitize user agent after initialization with comprehensive security checks."""
        # Handle None or empty user agent
        if not self.value:
            safe_result = ValidationResult(
                is_valid=True,
                sanitized_value=self.FALLBACK_VALUE,
                violations=[],
                risk_score=0,
                blocked_patterns=[]
            )
            object.__setattr__(self, 'value', self.FALLBACK_VALUE)
            object.__setattr__(self, '_validation_result', safe_result)
            return
        
        # Perform comprehensive security sanitization
        validation_result = input_sanitizer_service.sanitize_user_agent(
            self.value, 
            max_length=self.DEFAULT_MAX_LENGTH
        )
        
        # Store validation result for audit purposes
        object.__setattr__(self, '_validation_result', validation_result)
        
        # Always use the sanitized value (even if validation failed)
        # This ensures we never store unsafe user agent strings
        object.__setattr__(self, 'value', validation_result.sanitized_value)
        
        # Log security violations for monitoring
        if validation_result.violations:
            logger.security_warning(
                "User agent security violations detected",
                original_length=len(self.value) if hasattr(self, 'value') else 0,
                sanitized_length=len(validation_result.sanitized_value),
                risk_score=validation_result.risk_score,
                violation_count=len(validation_result.violations),
                has_critical_violations=validation_result.has_critical_violations,
                has_high_violations=validation_result.has_high_violations,
                blocked_patterns_count=len(validation_result.blocked_patterns)
            )
        
        # Log successful sanitization with security metadata
        logger.debug(
            "User agent sanitization completed",
            sanitized_length=len(validation_result.sanitized_value),
            risk_score=validation_result.risk_score,
            is_valid=validation_result.is_valid
        )
    
    @classmethod
    def create_safe(cls, value: Optional[str], max_length: Optional[int] = None) -> 'SecureUserAgent':
        """Create sanitized user agent with comprehensive safety checks.
        
        This factory method provides enhanced sanitization with:
        - Configurable maximum length
        - Automatic fallback for invalid input
        - Comprehensive security validation
        - Audit logging of sanitization attempts
        
        Args:
            value: Raw user agent string to sanitize (can be None)
            max_length: Maximum allowed length (defaults to DEFAULT_MAX_LENGTH)
            
        Returns:
            SecureUserAgent: Sanitized user agent object
        """
        # Handle None or empty input gracefully
        if not value:
            return cls("")
        
        # Apply length limit if specified
        if max_length and len(value) > max_length:
            value = value[:max_length]
            logger.debug(
                "User agent truncated to maximum length",
                original_length=len(value),
                max_length=max_length
            )
        
        try:
            return cls(value)
        except Exception as e:
            # Handle unexpected errors with graceful fallback
            logger.error(
                "Unexpected error during user agent sanitization",
                error=str(e),
                error_type=type(e).__name__,
                user_agent_length=len(value) if value else 0
            )
            
            # Return safe fallback value
            return cls("")
    
    def mask_for_logging(self, max_visible: int = 50) -> str:
        """Return masked user agent for secure logging.
        
        This method provides safe logging representation that prevents
        information leakage while maintaining audit trail utility.
        
        Args:
            max_visible: Maximum number of characters to show
            
        Returns:
            str: Masked user agent string
        """
        if len(self.value) <= max_visible:
            return self.value
        return self.value[:max_visible] + "***"
    
    def get_security_metadata(self) -> dict:
        """Get comprehensive security metadata for audit purposes.
        
        Returns:
            dict: Security metadata including risk score, violations, etc.
        """
        return {
            'risk_score': self._validation_result.risk_score,
            'violations': [
                {
                    'type': violation_type,
                    'severity': severity.value
                }
                for violation_type, severity in self._validation_result.violations
            ],
            'blocked_patterns': self._validation_result.blocked_patterns,
            'is_valid': self._validation_result.is_valid,
            'has_critical_violations': self._validation_result.has_critical_violations,
            'has_high_violations': self._validation_result.has_high_violations,
            'sanitized_length': len(self.value),
            'control_chars_removed': any(
                'control_characters_removed' in violation_type 
                for violation_type, _ in self._validation_result.violations
            )
        }
    
    def is_suspicious(self) -> bool:
        """Check if user agent has suspicious characteristics.
        
        Returns:
            bool: True if user agent appears suspicious
        """
        return (
            self._validation_result.risk_score > 50 or
            self._validation_result.has_critical_violations or
            len(self._validation_result.blocked_patterns) > 0
        )
    
    def is_safe_for_logging(self) -> bool:
        """Check if user agent is safe for logging without additional sanitization.
        
        Returns:
            bool: True if safe for direct logging
        """
        return (
            self._validation_result.risk_score < 30 and
            not self._validation_result.has_critical_violations and
            not any(
                'control_characters_removed' in violation_type 
                for violation_type, _ in self._validation_result.violations
            )
        )
    
    def get_browser_info(self) -> dict:
        """Extract basic browser information from sanitized user agent.
        
        This method provides safe browser detection without exposing
        potentially malicious content.
        
        Returns:
            dict: Basic browser information (safe subset)
        """
        user_agent_lower = self.value.lower()
        
        # Safe browser detection patterns
        browser_patterns = {
            'chrome': 'chrome' in user_agent_lower,
            'firefox': 'firefox' in user_agent_lower,
            'safari': 'safari' in user_agent_lower and 'chrome' not in user_agent_lower,
            'edge': 'edge' in user_agent_lower,
            'opera': 'opera' in user_agent_lower,
            'mobile': any(mobile in user_agent_lower for mobile in ['mobile', 'android', 'iphone'])
        }
        
        return {
            'detected_browser': next((browser for browser, detected in browser_patterns.items() if detected), 'unknown'),
            'is_mobile': browser_patterns['mobile'],
            'is_suspicious': self.is_suspicious(),
            'risk_score': self._validation_result.risk_score
        }
    
    def __str__(self) -> str:
        """String representation of the sanitized user agent."""
        return self.value
    
    def __len__(self) -> int:
        """Length of the sanitized user agent."""
        return len(self.value)
    
    def __eq__(self, other) -> bool:
        """Equality comparison."""
        if isinstance(other, SecureUserAgent):
            return self.value == other.value
        if isinstance(other, str):
            # Create temporary secure user agent for comparison
            try:
                other_secure = SecureUserAgent.create_safe(other)
                return self.value == other_secure.value
            except Exception:
                # Fallback to basic comparison
                return self.value == other
        return False
    
    def __hash__(self) -> int:
        """Hash for use in sets and dictionaries."""
        return hash(self.value)
    
    def __repr__(self) -> str:
        """Developer representation with security metadata."""
        return (
            f"SecureUserAgent(value='{self.mask_for_logging(30)}', "
            f"risk_score={self._validation_result.risk_score}, "
            f"violations={len(self._validation_result.violations)})"
        ) 