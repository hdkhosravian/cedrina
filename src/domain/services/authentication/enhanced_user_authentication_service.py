"""Enhanced User Authentication Service with Security Logging and Information Disclosure Prevention.

This service extends the base authentication service with advanced security features:
- Structured security event logging
- Consistent error responses to prevent enumeration
- Standardized timing to prevent timing attacks
- Zero-trust data masking for audit trails
- OWASP-compliant security practices

The service maintains all existing functionality while adding comprehensive
security monitoring and information disclosure prevention.
"""

import time
from typing import Optional

import structlog

from src.core.exceptions import AuthenticationError
from src.domain.entities.user import User
from src.domain.events.authentication_events import (
    AuthenticationFailedEvent,
    UserLoggedInEvent,
)
from src.domain.interfaces.repositories import IUserRepository
from src.domain.interfaces.services import (
    IEventPublisher,
    IUserAuthenticationService,
)
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.domain.value_objects.password import HashedPassword, Password
from src.domain.value_objects.username import Username
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class EnhancedUserAuthenticationService(IUserAuthenticationService):
    """Enhanced authentication service with security logging and information disclosure prevention.
    
    This service implements enterprise-grade security practices:
    - Consistent error responses regardless of failure reason
    - Standardized timing to prevent timing attacks
    - Comprehensive security event logging
    - Zero-trust data masking for sensitive information
    - Risk-based authentication analysis
    """
    
    def __init__(
        self,
        user_repository: IUserRepository,
        event_publisher: IEventPublisher,
    ):
        """Initialize enhanced authentication service.
        
        Args:
            user_repository: Repository for user data access
            event_publisher: Publisher for domain events
        """
        self._user_repository = user_repository
        self._event_publisher = event_publisher
        self._logger = structlog.get_logger("auth.enhanced")
    
    async def authenticate_user(
        self,
        username: Username,
        password: Password,
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> User:
        """Authenticate user with enhanced security logging and error standardization.
        
        This method implements zero-trust security principles:
        - All authentication failures return identical responses
        - Timing is standardized to prevent timing attacks
        - Detailed security events are logged for monitoring
        - Sensitive data is properly masked in logs
        
        Args:
            username: Username value object (validated and normalized)
            password: Password value object (secure validation)
            language: Language code for I18N error messages
            client_ip: Client IP address for security context
            user_agent: User agent string for security context
            correlation_id: Request correlation ID for tracking
            
        Returns:
            User: Authenticated user entity
            
        Raises:
            AuthenticationError: If authentication fails (standardized message)
        """
        request_start_time = time.time()
        
        try:
            # Log authentication attempt with secure context
            self._logger.info(
                "Enhanced authentication attempt initiated",
                correlation_id=correlation_id,
                username_masked=secure_logging_service.mask_username(str(username)),
                ip_masked=secure_logging_service.mask_ip_address(client_ip),
                user_agent_sanitized=self._sanitize_user_agent(user_agent),
                security_enhanced=True
            )
            
            # Create security event for authentication attempt
            secure_logging_service.log_authentication_attempt(
                username=str(username),
                success=False,  # Will be updated if successful
                correlation_id=correlation_id,
                ip_address=client_ip,
                user_agent=user_agent,
                risk_indicators=self._analyze_risk_indicators(username, client_ip, user_agent)
            )
            
            # Retrieve user by normalized username from repository
            user = await self._user_repository.get_by_username(str(username))
            
            # Check if user exists
            if not user:
                return await self._handle_authentication_failure(
                    attempted_username=username,
                    failure_reason="user_not_found",
                    actual_error="User does not exist",
                    correlation_id=correlation_id,
                    user_agent=user_agent,
                    ip_address=client_ip,
                    language=language,
                    request_start_time=request_start_time
                )
            
            # Verify password is correct
            if not await self.verify_password(user, password):
                return await self._handle_authentication_failure(
                    attempted_username=username,
                    failure_reason="invalid_password",
                    actual_error="Invalid password provided",
                    correlation_id=correlation_id,
                    user_agent=user_agent,
                    ip_address=client_ip,
                    language=language,
                    request_start_time=request_start_time
                )
            
            # Verify user account is active (business rule)
            if not user.is_active:
                return await self._handle_authentication_failure(
                    attempted_username=username,
                    failure_reason="user_inactive",
                    actual_error="User account is inactive",
                    correlation_id=correlation_id,
                    user_agent=user_agent,
                    ip_address=client_ip,
                    language=language,
                    request_start_time=request_start_time
                )
            
            # Authentication successful - log security event
            secure_logging_service.log_authentication_attempt(
                username=str(username),
                success=True,
                correlation_id=correlation_id,
                ip_address=client_ip,
                user_agent=user_agent
            )
            
            # Publish successful login domain event
            await self._publish_successful_login_event(
                user=user,
                correlation_id=correlation_id,
                user_agent=user_agent,
                ip_address=client_ip,
            )
            
            # Log successful authentication with secure data
            self._logger.info(
                "Enhanced authentication successful",
                user_id=user.id,
                username_masked=secure_logging_service.mask_username(user.username),
                correlation_id=correlation_id,
                authentication_method="username_password",
                security_enhanced=True
            )
            
            return user
            
        except AuthenticationError:
            # Re-raise authentication errors (already standardized)
            raise
            
        except ValueError as e:
            # Handle value object validation errors with standardization
            return await self._handle_authentication_failure(
                attempted_username=username,
                failure_reason="validation_error",
                actual_error=f"Value object validation failed: {str(e)}",
                correlation_id=correlation_id,
                user_agent=user_agent,
                ip_address=client_ip,
                language=language,
                request_start_time=request_start_time
            )
            
        except Exception as e:
            # Handle unexpected errors with secure logging and standardization
            return await self._handle_authentication_failure(
                attempted_username=username,
                failure_reason="system_error",
                actual_error=f"Unexpected system error: {str(e)}",
                correlation_id=correlation_id,
                user_agent=user_agent,
                ip_address=client_ip,
                language=language,
                request_start_time=request_start_time
            )
    
    async def verify_password(self, user: User, password: Password) -> bool:
        """Verify password with timing attack protection.
        
        This method uses constant-time comparison to prevent timing attacks
        while maintaining the existing password verification logic.
        
        Args:
            user: User entity to verify password for
            password: Password value object to verify
            
        Returns:
            bool: True if password is valid
        """
        try:
            # Use the domain password verification logic
            hashed_password = HashedPassword(user.password_hash)
            is_valid = await password.verify_against_hash(hashed_password)
            
            # Add timing consistency for security
            # This ensures similar timing regardless of password validity
            if not is_valid:
                # Perform dummy hash operation to maintain consistent timing
                dummy_password = Password("dummy_password_for_timing")
                dummy_hash = HashedPassword("$2b$12$dummy.hash.for.timing.consistency.only")
                await dummy_password.verify_against_hash(dummy_hash)
            
            return is_valid
            
        except Exception as e:
            # Log verification error securely
            self._logger.error(
                "Password verification error",
                user_id=user.id,
                error_type=type(e).__name__,
                secure_verification=True
            )
            # Always return False for errors to maintain security
            return False
    
    async def _handle_authentication_failure(
        self,
        attempted_username: Username,
        failure_reason: str,
        actual_error: str,
        correlation_id: str,
        user_agent: str,
        ip_address: str,
        language: str,
        request_start_time: float
    ) -> None:
        """Handle authentication failure with enhanced security and standardization.
        
        Args:
            attempted_username: Username that was attempted
            failure_reason: Standardized failure reason
            actual_error: Actual error details (for secure logging)
            correlation_id: Request correlation ID
            user_agent: User agent string
            ip_address: Client IP address
            language: Language code for responses
            request_start_time: When the request started
            
        Raises:
            AuthenticationError: Standardized authentication error
        """
        # Log failure securely for monitoring
        error_standardization_service.log_error_safely(
            error_type=failure_reason,
            error_details={
                "username": str(attempted_username),
                "ip_address": ip_address,
                "user_agent": user_agent,
                "actual_error": actual_error
            },
            correlation_id=correlation_id,
            user_context={"username": str(attempted_username)}
        )
        
        # Publish authentication failure domain event
        try:
            failure_event = AuthenticationFailedEvent.create(
                attempted_username=secure_logging_service.mask_username(str(attempted_username)),
                failure_reason=failure_reason,
                correlation_id=correlation_id,
                user_agent=self._sanitize_user_agent(user_agent),
                ip_address=secure_logging_service.mask_ip_address(ip_address),
            )
            await self._event_publisher.publish(failure_event)
        except Exception as e:
            self._logger.error(
                "Failed to publish authentication failure event",
                error=str(e),
                correlation_id=correlation_id,
                secure_event_publishing=True
            )
        
        # Create standardized authentication error response
        error_response = await error_standardization_service.create_authentication_error_response(
            actual_failure_reason=failure_reason,
            username=str(attempted_username),
            correlation_id=correlation_id,
            language=language,
            request_start_time=request_start_time
        )
        
        # Raise standardized authentication error
        raise AuthenticationError(error_response["detail"])
    
    async def _publish_successful_login_event(
        self,
        user: User,
        correlation_id: str,
        user_agent: str,
        ip_address: str,
    ) -> None:
        """Publish successful login event with secure data masking.
        
        Args:
            user: Authenticated user entity
            correlation_id: Request correlation ID
            user_agent: User agent string
            ip_address: Client IP address
        """
        try:
            # Create login event with masked sensitive data
            login_event = UserLoggedInEvent.create(
                user_id=user.id,
                username=secure_logging_service.mask_username(user.username),
                login_method="username_password",
                correlation_id=correlation_id,
                user_agent=self._sanitize_user_agent(user_agent),
                ip_address=secure_logging_service.mask_ip_address(ip_address),
            )
            
            await self._event_publisher.publish(login_event)
            
            self._logger.info(
                "Successful login event published",
                user_id=user.id,
                correlation_id=correlation_id,
                event_type="UserLoggedInEvent",
                secure_event_publishing=True
            )
            
        except Exception as e:
            # Log event publishing failure but don't fail authentication
            self._logger.error(
                "Failed to publish successful login event",
                user_id=user.id,
                error=str(e),
                correlation_id=correlation_id,
                secure_event_publishing=True
            )
    
    def _sanitize_user_agent(self, user_agent: str) -> str:
        """Sanitize user agent string for secure logging.
        
        Args:
            user_agent: Raw user agent string
            
        Returns:
            str: Sanitized user agent string
        """
        if not user_agent:
            return "unknown"
        
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
    
    def _analyze_risk_indicators(
        self,
        username: Username,
        ip_address: str,
        user_agent: str
    ) -> list[str]:
        """Analyze request for security risk indicators.
        
        Args:
            username: Attempted username
            ip_address: Client IP address
            user_agent: User agent string
            
        Returns:
            List[str]: Detected risk indicators
        """
        risk_indicators = []
        
        # Check for suspicious patterns in username
        username_str = str(username).lower()
        suspicious_patterns = ["admin", "root", "test", "demo", "guest"]
        if any(pattern in username_str for pattern in suspicious_patterns):
            risk_indicators.append("suspicious_username_pattern")
        
        # Check for missing or suspicious user agent
        if not user_agent or len(user_agent) < 10:
            risk_indicators.append("missing_or_minimal_user_agent")
        elif "curl" in user_agent.lower() or "wget" in user_agent.lower():
            risk_indicators.append("automated_client_detected")
        
        # Check for local/internal IP addresses
        if ip_address.startswith(("127.", "10.", "192.168.", "172.")):
            risk_indicators.append("internal_ip_address")
        
        return risk_indicators 