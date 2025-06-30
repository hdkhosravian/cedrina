"""Input sanitization and validation service for secure input handling.

This service provides comprehensive input sanitization and validation capabilities
to prevent various attack vectors including injection attacks, log poisoning,
and data corruption. It follows security best practices and OWASP guidelines.
"""

import html
import re
import unicodedata
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum

import structlog

logger = structlog.get_logger(__name__)


class ValidationSeverity(str, Enum):
    """Severity levels for validation violations."""
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ValidationResult:
    """Result of input validation with security metadata."""
    is_valid: bool
    sanitized_value: str
    violations: List[Tuple[str, ValidationSeverity]]
    risk_score: int  # 0-100 scale
    blocked_patterns: List[str]
    
    @property
    def has_critical_violations(self) -> bool:
        """Check if validation result has critical security violations."""
        return any(severity == ValidationSeverity.CRITICAL for _, severity in self.violations)
    
    @property
    def has_high_violations(self) -> bool:
        """Check if validation result has high-severity violations."""
        return any(severity == ValidationSeverity.HIGH for _, severity in self.violations)


class InputSanitizerService:
    """Advanced input sanitization service with comprehensive security controls.
    
    This service provides:
    - Unicode normalization and homograph attack prevention
    - Injection attack pattern detection and blocking
    - Log injection prevention and sanitization
    - Control character filtering
    - Security risk assessment and scoring
    - Comprehensive audit logging of security violations
    
    Security Features:
    - OWASP compliance for input validation
    - Zero-trust input sanitization approach
    - Layered security validation
    - Attack pattern recognition
    - Security event logging and monitoring
    """
    
    # Core security patterns - compiled for performance
    DANGEROUS_PATTERNS = {
        # SQL Injection patterns
        'sql_injection': [
            r'(?i)(union\s+select|drop\s+table|delete\s+from)',
            r'(?i)(exec\s*\(|execute\()',
            r'(?i)(script\s*:|javascript\s*:)',
            r'(;|--|/\*|\*/)',  # Removed quotes as they're common in user agents
        ],
        
        # LDAP Injection patterns  
        'ldap_injection': [
            r'[\(\)\*\&\|\!]',
            r'\\[0-9a-fA-F]{2}',  # LDAP escape sequences
        ],
        
        # Path traversal patterns
        'path_traversal': [
            r'\.\./|\.\.\\',
            r'(?i)(file://|ftp://)',
            r'[<>:"|?*]',  # Windows invalid filename chars
        ],
        
        # NoSQL injection patterns
        'nosql_injection': [
            r'(?i)(\$where|\$ne|\$gt|\$regex)',
            r'(?i)(function\s*\(|eval\s*\()',
        ],
        
        # Log injection patterns
        'log_injection': [
            r'[\r\n\x00-\x1f\x7f]',  # Control characters
            r'(?i)(script|iframe|object|embed)',
            r'[\x80-\xff]',  # High-bit characters that can cause encoding issues
        ],
        
        # Command injection patterns  
        'command_injection': [
            r'[;&|`$]',
            r'(?i)(bash|sh|cmd|powershell)',
        ],
        
        # XSS patterns
        'xss_patterns': [
            r'(?i)<script[^>]*>',
            r'(?i)javascript\s*:',
            r'(?i)on\w+\s*=',  # Event handlers
            r'(?i)(alert|confirm|prompt)\s*\(',
        ]
    }
    
    # Control characters and dangerous Unicode
    CONTROL_CHARS = set(range(0, 32)) | {127}  # ASCII control chars + DEL
    DANGEROUS_UNICODE_CATEGORIES = {'Cc', 'Cf', 'Co', 'Cs'}  # Control, format, private use, surrogates
    
    # Username-specific security patterns
    USERNAME_SECURITY_PATTERNS = {
        'reserved_names': {
            'admin', 'administrator', 'root', 'system', 'user', 'guest', 
            'public', 'anonymous', 'test', 'demo', 'null', 'undefined',
            'api', 'www', 'mail', 'ftp', 'smtp', 'imap', 'pop3'
        },
        'dangerous_prefixes': ['__', '.', '-'],
        'dangerous_suffixes': ['__', '.', '-'],
        'max_consecutive_specials': 2,
        'blocked_substrings': ['script', 'admin', 'root', 'system']
    }
    
    def __init__(self):
        """Initialize the input sanitizer with compiled patterns."""
        self._compiled_patterns = self._compile_security_patterns()
        
    def _compile_security_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile all security patterns for performance."""
        compiled = {}
        for category, patterns in self.DANGEROUS_PATTERNS.items():
            compiled[category] = [re.compile(pattern) for pattern in patterns]
        return compiled
    
    def sanitize_username(self, username: str, strict: bool = True) -> ValidationResult:
        """Sanitize and validate username with comprehensive security checks.
        
        This method implements enterprise-grade username validation with:
        - Unicode normalization (NFC) to prevent homograph attacks
        - Dangerous pattern detection and blocking
        - Reserved name checking
        - Character composition analysis
        - Security risk scoring
        
        Args:
            username: Raw username string to validate
            strict: If True, applies stricter validation rules
            
        Returns:
            ValidationResult: Comprehensive validation result with security metadata
        """
        if not username:
            return ValidationResult(
                is_valid=False,
                sanitized_value="",
                violations=[("empty_input", ValidationSeverity.HIGH)],
                risk_score=85,
                blocked_patterns=[]
            )
        
        violations = []
        blocked_patterns = []
        risk_score = 0
        
        # Step 1: Unicode normalization to prevent homograph attacks
        try:
            normalized = unicodedata.normalize('NFC', username.strip())
        except Exception as e:
            logger.warning("Unicode normalization failed", username_length=len(username), error=str(e))
            violations.append(("unicode_normalization_failed", ValidationSeverity.CRITICAL))
            risk_score += 50
            normalized = username.strip()
        
        # Step 2: Control character detection
        sanitized = self._remove_control_characters(normalized)
        if sanitized != normalized:
            violations.append(("control_characters_removed", ValidationSeverity.HIGH))
            risk_score += 30
        
        # Step 3: Dangerous Unicode category filtering
        sanitized, unicode_violations = self._filter_dangerous_unicode(sanitized)
        violations.extend(unicode_violations)
        risk_score += len(unicode_violations) * 20
        
        # Step 4: Security pattern analysis
        pattern_violations, pattern_blocked = self._analyze_security_patterns(sanitized)
        violations.extend(pattern_violations)
        blocked_patterns.extend(pattern_blocked)
        risk_score += len(pattern_violations) * 15
        
        # Step 5: Username-specific validation
        username_violations = self._validate_username_rules(sanitized, strict)
        violations.extend(username_violations)
        risk_score += len(username_violations) * 10
        
        # Step 6: Length and format validation
        length_violations = self._validate_length_and_format(sanitized)
        violations.extend(length_violations)
        risk_score += len(length_violations) * 5
        
        # Final risk score capping
        risk_score = min(risk_score, 100)
        is_valid = (
            risk_score < 50 and 
            not any(
                severity in {ValidationSeverity.CRITICAL, ValidationSeverity.HIGH} 
                for _, severity in violations
            )
        )
        
        # Log security assessment
        if violations:
            logger.warning(
                "Username validation violations detected",
                original_length=len(username),
                sanitized_length=len(sanitized),
                violation_count=len(violations),
                risk_score=risk_score,
                blocked_patterns_count=len(blocked_patterns),
                is_valid=is_valid
            )
        
        return ValidationResult(
            is_valid=is_valid,
            sanitized_value=sanitized.lower(),  # Always normalize to lowercase
            violations=violations,
            risk_score=risk_score,
            blocked_patterns=blocked_patterns
        )
    
    def sanitize_user_agent(self, user_agent: str, max_length: int = 500) -> ValidationResult:
        """Sanitize user agent string to prevent log injection and XSS attacks.
        
        This method provides comprehensive user agent sanitization including:
        - Control character removal (prevents log injection)
        - XSS pattern detection and neutralization  
        - Length limiting to prevent DoS attacks
        - Encoding normalization
        - Suspicious pattern detection
        
        Args:
            user_agent: Raw user agent string from HTTP headers
            max_length: Maximum allowed length (default: 500 chars)
            
        Returns:
            ValidationResult: Sanitized user agent with security metadata
        """
        if not user_agent:
            return ValidationResult(
                is_valid=True,
                sanitized_value="unknown",
                violations=[],
                risk_score=0,
                blocked_patterns=[]
            )
        
        violations = []
        blocked_patterns = []
        risk_score = 0
        
        # Step 1: Length validation
        if len(user_agent) > max_length:
            violations.append(("excessive_length", ValidationSeverity.MEDIUM))
            risk_score += 20
            user_agent = user_agent[:max_length]
        
        # Step 2: Control character removal (critical for log injection prevention)
        sanitized = self._remove_control_characters(user_agent)
        if sanitized != user_agent:
            violations.append(("control_characters_removed", ValidationSeverity.HIGH))
            risk_score += 30
            
        # Step 3: XSS pattern detection
        xss_violations, xss_patterns = self._detect_xss_patterns(sanitized)
        violations.extend(xss_violations)
        blocked_patterns.extend(xss_patterns)
        risk_score += len(xss_violations) * 25
        
        # Step 4: HTML entity encoding for safety
        sanitized = html.escape(sanitized, quote=False)
        
        # Step 5: Additional suspicious pattern detection
        suspicious_violations = self._detect_suspicious_user_agent_patterns(sanitized)
        violations.extend(suspicious_violations)
        risk_score += len(suspicious_violations) * 15
        
        # Step 6: Unicode normalization
        try:
            sanitized = unicodedata.normalize('NFC', sanitized)
        except Exception:
            violations.append(("unicode_normalization_failed", ValidationSeverity.MEDIUM))
            risk_score += 15
        
        risk_score = min(risk_score, 100)
        is_valid = risk_score < 70  # More lenient for user agents
        
        # Log suspicious user agents
        if risk_score > 30:
            logger.warning(
                "Suspicious user agent detected",
                original_length=len(user_agent) if user_agent else 0,
                sanitized_length=len(sanitized),
                risk_score=risk_score,
                violation_count=len(violations)
            )
        
        return ValidationResult(
            is_valid=is_valid,
            sanitized_value=sanitized,
            violations=violations,
            risk_score=risk_score,
            blocked_patterns=blocked_patterns
        )
    
    def _remove_control_characters(self, text: str) -> str:
        """Remove ASCII control characters and dangerous Unicode."""
        return ''.join(
            char for char in text 
            if ord(char) not in self.CONTROL_CHARS and 
               unicodedata.category(char) not in self.DANGEROUS_UNICODE_CATEGORIES
        )
    
    def _filter_dangerous_unicode(self, text: str) -> Tuple[str, List[Tuple[str, ValidationSeverity]]]:
        """Filter dangerous Unicode characters and detect violations."""
        violations = []
        filtered_chars = []
        
        for char in text:
            category = unicodedata.category(char)
            if category in self.DANGEROUS_UNICODE_CATEGORIES:
                violations.append((f"dangerous_unicode_{category}", ValidationSeverity.HIGH))
            else:
                filtered_chars.append(char)
        
        return ''.join(filtered_chars), violations
    
    def _analyze_security_patterns(self, text: str) -> Tuple[List[Tuple[str, ValidationSeverity]], List[str]]:
        """Analyze text for dangerous security patterns."""
        violations = []
        blocked_patterns = []
        
        for category, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(text):
                    violations.append((f"{category}_detected", ValidationSeverity.HIGH))
                    blocked_patterns.append(f"{category}:{pattern.pattern}")
        
        return violations, blocked_patterns
    
    def _validate_username_rules(self, username: str, strict: bool) -> List[Tuple[str, ValidationSeverity]]:
        """Validate username against security rules."""
        violations = []
        rules = self.USERNAME_SECURITY_PATTERNS
        
        # Check reserved names
        if username.lower() in rules['reserved_names']:
            violations.append(("reserved_username", ValidationSeverity.CRITICAL))
        
        # Check dangerous prefixes/suffixes
        for prefix in rules['dangerous_prefixes']:
            if username.startswith(prefix):
                violations.append(("dangerous_prefix", ValidationSeverity.HIGH))
        
        for suffix in rules['dangerous_suffixes']:
            if username.endswith(suffix):
                violations.append(("dangerous_suffix", ValidationSeverity.HIGH))
        
        # Check consecutive special characters
        consecutive_count = 0
        max_consecutive = 0
        for char in username:
            if char in '_-':
                consecutive_count += 1
                max_consecutive = max(max_consecutive, consecutive_count)
            else:
                consecutive_count = 0
        
        if max_consecutive > rules['max_consecutive_specials']:
            violations.append(("excessive_consecutive_specials", ValidationSeverity.MEDIUM))
        
        # Check blocked substrings
        for blocked in rules['blocked_substrings']:
            if blocked in username.lower():
                violations.append(("blocked_substring", ValidationSeverity.HIGH))
        
        return violations
    
    def _validate_length_and_format(self, username: str) -> List[Tuple[str, ValidationSeverity]]:
        """Validate username length and basic format."""
        violations = []
        
        if len(username) < 3:
            violations.append(("too_short", ValidationSeverity.HIGH))
        elif len(username) > 30:
            violations.append(("too_long", ValidationSeverity.MEDIUM))
        
        # Basic alphanumeric + allowed specials check
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            violations.append(("invalid_characters", ValidationSeverity.HIGH))
        
        # Must start and end with alphanumeric
        if username and not username[0].isalnum():
            violations.append(("invalid_start_character", ValidationSeverity.MEDIUM))
        
        if username and not username[-1].isalnum():
            violations.append(("invalid_end_character", ValidationSeverity.MEDIUM))
        
        return violations
    
    def _detect_xss_patterns(self, text: str) -> Tuple[List[Tuple[str, ValidationSeverity]], List[str]]:
        """Detect XSS patterns in text."""
        violations = []
        blocked_patterns = []
        
        for pattern in self._compiled_patterns['xss_patterns']:
            if pattern.search(text):
                violations.append(("xss_pattern_detected", ValidationSeverity.CRITICAL))
                blocked_patterns.append(f"xss:{pattern.pattern}")
        
        return violations, blocked_patterns
    
    def _detect_suspicious_user_agent_patterns(self, user_agent: str) -> List[Tuple[str, ValidationSeverity]]:
        """Detect suspicious patterns in user agent strings."""
        violations = []
        
        # Check for SQL injection attempts (only obvious ones)
        sql_patterns = [
            r'(?i)(union\s+select|drop\s+table|delete\s+from)',
            r'(;|--|/\*|\*/)'
        ]
        if any(re.search(pattern, user_agent) for pattern in sql_patterns):
            violations.append(("sql_injection_attempt", ValidationSeverity.CRITICAL))
        
        # Check for command injection (only obvious shell commands)
        cmd_patterns = [
            r'[;&|`$](?![\w])',  # Command separators not followed by word chars
            r'(?i)\b(bash|sh|cmd|powershell)\b'
        ]
        if any(re.search(pattern, user_agent) for pattern in cmd_patterns):
            violations.append(("command_injection_attempt", ValidationSeverity.CRITICAL))
        
        # Check for excessive special characters (potential DoS)
        special_count = sum(1 for char in user_agent if not char.isalnum() and char not in ' -_./()')
        if len(user_agent) > 0 and special_count > len(user_agent) * 0.5:  # More than 50% special chars
            violations.append(("excessive_special_characters", ValidationSeverity.MEDIUM))
        
        # Check for repeated patterns (potential DoS)
        if len(user_agent) > 20 and len(set(user_agent)) < len(user_agent) * 0.05:  # Less than 5% unique chars
            violations.append(("repetitive_pattern", ValidationSeverity.MEDIUM))
        
        return violations


# Global instance for dependency injection
input_sanitizer_service = InputSanitizerService()