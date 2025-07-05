"""Secure Username value object with advanced validation and security controls.

This module provides an enterprise-grade Username value object that integrates
with the input sanitization service to provide comprehensive security validation,
attack pattern detection, and audit logging.
"""

from dataclasses import dataclass
from typing import ClassVar, Optional

import structlog

from src.domain.validation.input_sanitizer import (
    input_sanitizer_service,
    ValidationResult,
    ValidationSeverity
)
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class UsernameValidationError(ValueError):
    """Exception raised when username validation fails with security details."""
    
    def __init__(self, message: str, validation_result: ValidationResult):
        super().__init__(message)
        self.validation_result = validation_result
        self.risk_score = validation_result.risk_score
        self.violations = validation_result.violations
        self.blocked_patterns = validation_result.blocked_patterns


@dataclass(frozen=True)
class SecureUsername:
    """Secure username value object with advanced validation and security controls.
    
    This value object provides enterprise-grade username validation including:
    - Advanced injection attack detection (SQL, LDAP, NoSQL, XSS)
    - Unicode normalization and homograph attack prevention
    - Control character filtering and sanitization
    - Reserved name and dangerous pattern blocking
    - Comprehensive security risk assessment
    - Audit logging of security violations
    
    Security Features:
    - Zero-trust input validation approach
    - OWASP-compliant security controls
    - Layered defense against multiple attack vectors
    - Comprehensive audit trails for security monitoring
    - Risk-based validation with configurable strictness
    
    Business Rules:
    - 3-30 characters in length
    - Alphanumeric characters, underscores, hyphens only
    - Cannot start or end with special characters
    - Case-insensitive (normalized to lowercase)
    - No consecutive special characters
    - Blocks reserved system names
    - Prevents common attack patterns
    """
    
    value: str
    _validation_result: Optional[ValidationResult] = None
    
    # Business rule constants
    MIN_LENGTH: ClassVar[int] = 3
    MAX_LENGTH: ClassVar[int] = 30
    
    def __post_init__(self):
        """Validate username after initialization with advanced security checks."""
        if not self.value:
            raise UsernameValidationError(
                "Username cannot be empty",
                ValidationResult(
                    is_valid=False,
                    sanitized_value="",
                    violations=[("empty_input", ValidationSeverity.HIGH)],
                    risk_score=85,
                    blocked_patterns=[]
                )
            )
        
        # If validation result is already provided, use it
        if self._validation_result is not None:
            validation_result = self._validation_result
        else:
        # Perform comprehensive security validation
        validation_result = input_sanitizer_service.sanitize_username(
            self.value, 
            strict=True
        )
        # Store validation result for audit purposes
        object.__setattr__(self, '_validation_result', validation_result)
        
        # Check if validation passed security requirements
        if not validation_result.is_valid:
            # Log security violation for monitoring
            logger.security_warning(
                "Username validation failed with security violations",
                original_username_length=len(self.value),
                risk_score=validation_result.risk_score,
                violation_count=len(validation_result.violations),
                has_critical_violations=validation_result.has_critical_violations,
                has_high_violations=validation_result.has_high_violations,
                blocked_patterns_count=len(validation_result.blocked_patterns)
            )
            
            # Generate user-friendly error message based on violation severity
            error_message = self._generate_user_error_message(validation_result)
            raise UsernameValidationError(error_message, validation_result)
        
        # Update the value with the sanitized version
        object.__setattr__(self, 'value', validation_result.sanitized_value)
        
        # Log successful validation with security metadata
        logger.debug(
            "Username validation successful",
            sanitized_username=self.mask_for_logging(),
            risk_score=validation_result.risk_score,
            validation_passed=True
        )
    
    @classmethod
    def create_safe(cls, value: str, language: str = "en") -> 'SecureUsername':
        """Create username with comprehensive safety checks and localized errors.
        
        This factory method provides enhanced error handling with:
        - Localized error messages for better user experience
        - Detailed security validation results
        - Audit logging of validation attempts
        - Risk assessment and security scoring
        
        Args:
            value: Raw username string to validate
            language: Language code for localized error messages
            
        Returns:
            SecureUsername: Validated and sanitized username object
            
        Raises:
            UsernameValidationError: If username fails security validation
        """
        try:
            username = cls(value)
            
            # Additional business rule validation
            if username.is_system_username():
                validation_result = ValidationResult(
                    is_valid=False,
                    sanitized_value=username.value,
                    violations=[("reserved_username", ValidationSeverity.CRITICAL)],
                    risk_score=90,
                    blocked_patterns=["system_reserved"]
                )
                
                logger.security_warning(
                    "Attempt to use reserved system username",
                    username=username.mask_for_logging(),
                    risk_score=90
                )
                
                raise UsernameValidationError(
                    get_translated_message("username_reserved_for_system", language),
                    validation_result
                )
            
            return username
            
        except UsernameValidationError:
            # Re-raise validation errors with proper context
            raise
        except Exception as e:
            # Handle unexpected errors with security logging
            logger.error(
                "Unexpected error during username validation",
                error=str(e),
                error_type=type(e).__name__,
                username_length=len(value) if value else 0
            )
            
            validation_result = ValidationResult(
                is_valid=False,
                sanitized_value="",
                violations=[("validation_system_error", ValidationSeverity.CRITICAL)],
                risk_score=100,
                blocked_patterns=[]
            )
            
            raise UsernameValidationError(
                get_translated_message("username_validation_system_error", language),
                validation_result
            ) from e
    
    def mask_for_logging(self) -> str:
        """Return masked username for secure logging.
        
        This method provides safe logging representation that prevents
        information leakage while maintaining audit trail utility.
        
        Returns:
            str: Masked username (first 2 chars + asterisks)
        """
        if len(self.value) <= 2:
            return "*" * len(self.value)
        return self.value[:2] + "*" * (len(self.value) - 2)
    
    def is_system_username(self) -> bool:
        """Check if this is a reserved system username.
        
        Returns:
            bool: True if username is reserved for system use
        """
        # Use the sanitization service's reserved names list
        reserved_names = input_sanitizer_service.USERNAME_SECURITY_PATTERNS['reserved_names']
        return self.value.lower() in reserved_names
    
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
            'has_high_violations': self._validation_result.has_high_violations
        }
    
    def _generate_user_error_message(self, validation_result: ValidationResult) -> str:
        """Generate user-friendly error message based on validation violations.
        
        Args:
            validation_result: Validation result with violations
            
        Returns:
            str: User-friendly error message
        """
        # Check for critical violations first
        if validation_result.has_critical_violations:
            return get_translated_message("username_security_violation", "en")
        
        # Check for high-severity violations
        if validation_result.has_high_violations:
            return get_translated_message("username_invalid_format", "en")
        
        # Check specific violation types for targeted messages
        violation_types = {violation_type for violation_type, _ in validation_result.violations}
        
        if "too_short" in violation_types:
            return get_translated_message("username_too_short", "en")
        elif "too_long" in violation_types:
            return get_translated_message("username_too_long", "en")
        elif "invalid_characters" in violation_types:
            return get_translated_message("invalid_username_characters", "en")
        elif "reserved_username" in violation_types:
            return get_translated_message("username_reserved_for_system", "en")
        else:
            # Generic error for other violations
            return get_translated_message("username_invalid_format", "en")
    
    def __str__(self) -> str:
        """String representation of the username."""
        return self.value
    
    def __eq__(self, other) -> bool:
        """Equality comparison with security-aware normalization."""
        if isinstance(other, SecureUsername):
            return self.value == other.value
        if isinstance(other, str):
            # Normalize the comparison string for consistency
            try:
                other_validation = input_sanitizer_service.sanitize_username(other, strict=False)
                return self.value == other_validation.sanitized_value
            except Exception:
                # Fallback to basic comparison if sanitization fails
                return self.value == other.lower().strip()
        return False
    
    def __hash__(self) -> int:
        """Hash for use in sets and dictionaries."""
        return hash(self.value)
    
    def __repr__(self) -> str:
        """Developer representation with security metadata."""
        return (
            f"SecureUsername(value='{self.mask_for_logging()}', "
            f"risk_score={self._validation_result.risk_score}, "
            f"violations={len(self._validation_result.violations)})"
        ) 