"""Error Standardization Service for Preventing Information Disclosure.

This service provides consistent error responses and timing behavior across
all authentication and authorization endpoints to prevent enumeration attacks,
timing attacks, and other information disclosure vulnerabilities.

Key Security Features:
- Consistent error messages regardless of actual failure reason
- Standardized response timing to prevent timing attacks
- Generic error codes that don't reveal system internals
- Safe error logging that doesn't expose sensitive information
- OWASP-compliant error handling practices
"""

import asyncio
import hashlib
import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

import structlog

from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class ErrorCategory(Enum):
    """Standard error categories for consistent handling."""
    
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    SYSTEM = "system"
    RATE_LIMIT = "rate_limit"
    RESOURCE_NOT_FOUND = "resource_not_found"


class TimingPattern(Enum):
    """Standard timing patterns for preventing timing attacks."""
    
    FAST = "fast"          # 50-100ms for simple validations
    MEDIUM = "medium"      # 200-400ms for standard operations
    SLOW = "slow"          # 500-800ms for complex operations like hashing
    VARIABLE = "variable"  # Random timing within bounds


@dataclass(frozen=True)
class StandardizedError:
    """Standardized error response that prevents information disclosure."""
    
    category: ErrorCategory
    message_key: str
    http_status: int
    timing_pattern: TimingPattern
    correlation_id: Optional[str] = None
    additional_headers: Optional[Dict[str, str]] = None


class ErrorStandardizationService:
    """Service for creating consistent error responses across all endpoints.
    
    This service implements security best practices:
    - All authentication failures return identical messages
    - Response timing is standardized to prevent timing attacks
    - Error codes are generic and don't reveal system internals
    - Detailed error information is logged securely for monitoring
    """
    
    # Standard timing ranges (in seconds)
    TIMING_RANGES = {
        TimingPattern.FAST: (0.05, 0.1),
        TimingPattern.MEDIUM: (0.2, 0.4),
        TimingPattern.SLOW: (0.5, 0.8),
        TimingPattern.VARIABLE: (0.1, 0.6)
    }
    
    # Standard error definitions
    STANDARD_ERRORS = {
        # Authentication errors - all return the same generic message
        "invalid_credentials": StandardizedError(
            category=ErrorCategory.AUTHENTICATION,
            message_key="invalid_credentials_generic",
            http_status=401,
            timing_pattern=TimingPattern.SLOW
        ),
        "user_not_found": StandardizedError(
            category=ErrorCategory.AUTHENTICATION,
            message_key="invalid_credentials_generic",
            http_status=401,
            timing_pattern=TimingPattern.SLOW
        ),
        "inactive_account": StandardizedError(
            category=ErrorCategory.AUTHENTICATION,
            message_key="invalid_credentials_generic",
            http_status=401,
            timing_pattern=TimingPattern.SLOW
        ),
        "locked_account": StandardizedError(
            category=ErrorCategory.AUTHENTICATION,
            message_key="invalid_credentials_generic",
            http_status=401,
            timing_pattern=TimingPattern.SLOW
        ),
        "expired_credentials": StandardizedError(
            category=ErrorCategory.AUTHENTICATION,
            message_key="invalid_credentials_generic",
            http_status=401,
            timing_pattern=TimingPattern.SLOW
        ),
        
        # Authorization errors
        "insufficient_permissions": StandardizedError(
            category=ErrorCategory.AUTHORIZATION,
            message_key="access_denied_generic",
            http_status=403,
            timing_pattern=TimingPattern.MEDIUM
        ),
        "resource_forbidden": StandardizedError(
            category=ErrorCategory.AUTHORIZATION,
            message_key="access_denied_generic",
            http_status=403,
            timing_pattern=TimingPattern.MEDIUM
        ),
        
        # Validation errors
        "invalid_input": StandardizedError(
            category=ErrorCategory.VALIDATION,
            message_key="invalid_input_generic",
            http_status=400,
            timing_pattern=TimingPattern.FAST
        ),
        "malformed_request": StandardizedError(
            category=ErrorCategory.VALIDATION,
            message_key="invalid_input_generic",
            http_status=400,
            timing_pattern=TimingPattern.FAST
        ),
        
        # System errors
        "internal_error": StandardizedError(
            category=ErrorCategory.SYSTEM,
            message_key="service_temporarily_unavailable",
            http_status=500,
            timing_pattern=TimingPattern.MEDIUM
        ),
        "service_unavailable": StandardizedError(
            category=ErrorCategory.SYSTEM,
            message_key="service_temporarily_unavailable",
            http_status=503,
            timing_pattern=TimingPattern.MEDIUM
        ),
        
        # Rate limiting
        "rate_limited": StandardizedError(
            category=ErrorCategory.RATE_LIMIT,
            message_key="too_many_requests_generic",
            http_status=429,
            timing_pattern=TimingPattern.FAST,
            additional_headers={"Retry-After": "60"}
        ),
        
        # Resource not found - be careful not to leak existence information
        "resource_not_found": StandardizedError(
            category=ErrorCategory.RESOURCE_NOT_FOUND,
            message_key="resource_not_accessible",
            http_status=404,
            timing_pattern=TimingPattern.MEDIUM
        )
    }
    
    def __init__(self):
        """Initialize error standardization service."""
        self._logger = structlog.get_logger("security.errors")
        self._request_timings: Dict[str, float] = {}
    
    async def create_standardized_response(
        self,
        error_type: str,
        actual_error: Optional[str] = None,
        correlation_id: Optional[str] = None,
        language: str = "en",
        request_start_time: Optional[float] = None
    ) -> Dict[str, Any]:
        """Create a standardized error response with consistent timing.
        
        Args:
            error_type: Type of error from STANDARD_ERRORS
            actual_error: Actual error details (for logging only)
            correlation_id: Request correlation ID
            language: Language code for i18n
            request_start_time: When the request started (for timing)
            
        Returns:
            Dict: Standardized error response
        """
        # Get standard error definition
        standard_error = self.STANDARD_ERRORS.get(
            error_type, 
            self.STANDARD_ERRORS["internal_error"]
        )
        
        # Log actual error details for monitoring (secure logging)
        if actual_error:
            self._logger.warning(
                "Standardized error response generated",
                error_type=error_type,
                actual_error_hash=hashlib.sha256(actual_error.encode()).hexdigest()[:16],
                standard_message_key=standard_error.message_key,
                correlation_id=correlation_id,
                category=standard_error.category.value
            )
        
        # Apply standardized timing
        await self._apply_standard_timing(
            standard_error.timing_pattern,
            correlation_id,
            request_start_time
        )
        
        # Create response
        response = {
            "detail": get_translated_message(standard_error.message_key, language),
            "error_code": standard_error.category.value.upper(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        if correlation_id:
            response["correlation_id"] = correlation_id
        
        return response
    
    async def create_authentication_error_response(
        self,
        actual_failure_reason: str,
        username: Optional[str] = None,
        correlation_id: Optional[str] = None,
        language: str = "en",
        request_start_time: Optional[float] = None
    ) -> Dict[str, Any]:
        """Create standardized authentication error response.
        
        All authentication failures return the same response regardless
        of the actual reason (user not found, wrong password, inactive account, etc.)
        
        Args:
            actual_failure_reason: Actual reason for failure (logged only)
            username: Attempted username (logged securely)
            correlation_id: Request correlation ID
            language: Language code
            request_start_time: Request start time for timing
            
        Returns:
            Dict: Standardized authentication error response
        """
        # Log actual failure for security monitoring
        self._logger.warning(
            "Authentication failure standardized",
            failure_reason=actual_failure_reason,
            username_hash=hashlib.sha256(username.encode()).hexdigest()[:16] if username else None,
            correlation_id=correlation_id,
            response_standardized=True
        )
        
        # Always return the same error type for authentication failures
        return await self.create_standardized_response(
            error_type="invalid_credentials",
            actual_error=f"{actual_failure_reason} for user {username[:2] + '***' if username else 'unknown'}",
            correlation_id=correlation_id,
            language=language,
            request_start_time=request_start_time
        )
    
    async def _apply_standard_timing(
        self,
        timing_pattern: TimingPattern,
        correlation_id: Optional[str] = None,
        request_start_time: Optional[float] = None
    ) -> None:
        """Apply standardized timing to prevent timing attacks.
        
        Args:
            timing_pattern: Desired timing pattern
            correlation_id: Request correlation ID
            request_start_time: When the request started
        """
        current_time = time.time()
        
        # Calculate target timing
        min_time, max_time = self.TIMING_RANGES[timing_pattern]
        
        if timing_pattern == TimingPattern.VARIABLE:
            # Use correlation ID for deterministic but variable timing
            if correlation_id:
                seed = int(hashlib.md5(correlation_id.encode()).hexdigest()[:8], 16)
                random.seed(seed)
            target_time = random.uniform(min_time, max_time)
        else:
            # Use consistent timing within range
            target_time = (min_time + max_time) / 2
        
        # Calculate elapsed time
        elapsed = current_time - (request_start_time or current_time)
        
        # Sleep if we need more time to reach target
        sleep_time = target_time - elapsed
        if sleep_time > 0:
            await asyncio.sleep(sleep_time)
        
        # Log timing for monitoring
        self._logger.debug(
            "Standardized timing applied",
            timing_pattern=timing_pattern.value,
            target_time=target_time,
            elapsed_time=elapsed,
            sleep_time=max(0, sleep_time),
            correlation_id=correlation_id
        )
    
    def get_safe_error_message(
        self,
        error_category: ErrorCategory,
        language: str = "en"
    ) -> str:
        """Get a safe, generic error message for a category.
        
        Args:
            error_category: Category of error
            language: Language code
            
        Returns:
            str: Safe error message
        """
        message_keys = {
            ErrorCategory.AUTHENTICATION: "invalid_credentials_generic",
            ErrorCategory.AUTHORIZATION: "access_denied_generic",
            ErrorCategory.VALIDATION: "invalid_input_generic",
            ErrorCategory.SYSTEM: "service_temporarily_unavailable",
            ErrorCategory.RATE_LIMIT: "too_many_requests_generic",
            ErrorCategory.RESOURCE_NOT_FOUND: "resource_not_accessible"
        }
        
        message_key = message_keys.get(error_category, "service_temporarily_unavailable")
        return get_translated_message(message_key, language)
    
    def log_error_safely(
        self,
        error_type: str,
        error_details: Dict[str, Any],
        correlation_id: Optional[str] = None,
        user_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log error details safely without exposing sensitive information.
        
        Args:
            error_type: Type of error
            error_details: Error details to log
            correlation_id: Request correlation ID
            user_context: User context (will be sanitized)
        """
        # Sanitize user context
        safe_user_context = {}
        if user_context:
            safe_user_context = {
                "user_id": user_context.get("user_id"),
                "has_username": bool(user_context.get("username")),
                "role": user_context.get("role"),
                "is_authenticated": user_context.get("is_authenticated", False)
            }
        
        # Sanitize error details
        safe_error_details = {}
        for key, value in error_details.items():
            if key in ["username", "email", "password"]:
                # Hash sensitive fields
                safe_error_details[f"{key}_hash"] = hashlib.sha256(str(value).encode()).hexdigest()[:16]
            elif key in ["ip_address"]:
                # Mask IP addresses
                safe_error_details[f"{key}_masked"] = self._mask_ip(str(value))
            else:
                safe_error_details[key] = value
        
        self._logger.error(
            "Error handled safely",
            error_type=error_type,
            error_details=safe_error_details,
            user_context=safe_user_context,
            correlation_id=correlation_id,
            secure_logging=True
        )
    
    def _mask_ip(self, ip_address: str) -> str:
        """Mask IP address for privacy compliance."""
        if "." in ip_address:
            parts = ip_address.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.***"
        return ip_address[:8] + "***"


# Global error standardization service instance
error_standardization_service = ErrorStandardizationService() 