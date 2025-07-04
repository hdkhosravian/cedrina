"""User Authentication Service with Security Logging and Information Disclosure Prevention.

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
from src.domain.interfaces import (
    IEventPublisher,
    IUserAuthenticationService,
)
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.domain.value_objects.password import HashedPassword, Password
from src.domain.value_objects.username import Username
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class UserAuthenticationSecurityService(IUserAuthenticationService):
    """Authentication service with security logging and information disclosure prevention.
    
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
        """Initialize authentication service with security features.
        
        Args:
            user_repository: Repository for user data access
            event_publisher: Publisher for domain events
        """
        self._user_repository = user_repository
        self._event_publisher = event_publisher
        self._logger = structlog.get_logger("auth.security")
    
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
                "Authentication attempt with security features initiated",
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
                "Authentication with security features successful",
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
            # Handle unexpected errors with standardization
            return await self._handle_authentication_failure(
                attempted_username=username,
                failure_reason="system_error",
                actual_error=f"System error: {str(e)}",
                correlation_id=correlation_id,
                user_agent=user_agent,
                ip_address=client_ip,
                language=language,
                request_start_time=request_start_time
            )
    
    async def verify_password(self, user: User, password: Password) -> bool:
        """Verify password for user using domain value objects with security logging.
        
        Args:
            user: User entity with hashed password
            password: Password value object to verify against user's hashed password
            
        Returns:
            bool: True if password matches user's hashed password, False otherwise
            
        Security Features:
        - Constant-time comparison prevents timing attacks
        - No sensitive data in logs
        - Fail-safe error handling
        - Domain value object validation
        """
        try:
            # Validate inputs
            if not user or not user.hashed_password or not password:
                self._logger.debug(
                    "Password verification failed - missing data",
                    user_id=user.id if user else None,
                    has_hashed_password=bool(user and user.hashed_password),
                    has_password=bool(password),
                    security_enhanced=True
                )
                return False
            
            # Use domain value object for secure password verification
            # Delegate to the Password's verify_against_hash method for constant-time comparison
            is_valid = password.verify_against_hash(user.hashed_password)
            
            self._logger.debug(
                "Password verification completed with security",
                user_id=user.id,
                is_valid=is_valid,
                verification_method="constant_time_comparison",
                security_enhanced=True
            )
            
            return is_valid
            
        except Exception as e:
            # Log error without exposing sensitive information
            self._logger.error(
                "Password verification error with security context",
                user_id=user.id if user else None,
                error=str(e),
                error_type=type(e).__name__,
                security_enhanced=True
            )
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
        """Handle authentication failure with consistent responses and timing.
        
        This method implements zero-trust security by:
        - Standardizing response timing to prevent enumeration
        - Masking actual failure reasons in responses
        - Logging detailed failure information securely
        - Publishing security events for monitoring
        
        Args:
            attempted_username: Username that was attempted
            failure_reason: Internal reason for failure
            actual_error: Actual error that occurred
            correlation_id: Request correlation ID
            user_agent: User agent string
            ip_address: Client IP address
            language: Language for error messages
            request_start_time: When request started (for timing standardization)
            
        Raises:
            AuthenticationError: Standardized authentication error
        """
        # Log detailed failure information securely
        self._logger.warning(
            "Authentication failure with security context",
            username_masked=secure_logging_service.mask_username(str(attempted_username)),
            failure_reason=failure_reason,
            actual_error=actual_error,
            correlation_id=correlation_id,
            ip_masked=secure_logging_service.mask_ip_address(ip_address),
            user_agent_sanitized=self._sanitize_user_agent(user_agent),
            security_enhanced=True
        )
        
        # Create and publish authentication failure event
        failure_event = AuthenticationFailedEvent.create(
            attempted_username=str(attempted_username),
            failure_reason=failure_reason,
            correlation_id=correlation_id,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        
        await self._event_publisher.publish(failure_event)
        
        # Log security event
        secure_logging_service.log_authentication_attempt(
            username=str(attempted_username),
            success=False,
            correlation_id=correlation_id,
            ip_address=ip_address,
            user_agent=user_agent,
            failure_reason=failure_reason
        )
        
        # Apply standardized timing to prevent timing attacks
        elapsed_time = time.time() - request_start_time
        await error_standardization_service.apply_standard_timing(elapsed_time)
        
        # Create standardized error response
        standardized_response = await error_standardization_service.create_standardized_response(
            error_type="authentication_failed",
            actual_error=actual_error,
            correlation_id=correlation_id,
            language=language
        )
        
        # Raise standardized authentication error
        raise AuthenticationError(message=standardized_response["detail"])
    
    async def _publish_successful_login_event(
        self,
        user: User,
        correlation_id: str,
        user_agent: str,
        ip_address: str,
    ) -> None:
        """Publish successful login domain event with security context.
        
        This method publishes successful login events for audit trails and
        security monitoring. It captures important security context information
        for compliance and monitoring purposes.
        
        Args:
            user: Successfully authenticated user entity
            correlation_id: Request correlation ID for tracing
            user_agent: Browser/client user agent for security context
            ip_address: Client IP address for security context
            
        Domain Events Published:
        - UserLoggedInEvent: Contains user information and security context
        """
        try:
            # Create and publish successful login domain event
            login_event = UserLoggedInEvent.create(
                user_id=user.id,
                username=user.username,
                correlation_id=correlation_id,
                user_agent=user_agent,
                ip_address=ip_address,
                previous_login_at=getattr(user, 'last_login_at', None),
            )
            
            await self._event_publisher.publish(login_event)
            
            self._logger.info(
                "Login event published with security context",
                user_id=user.id,
                correlation_id=correlation_id,
                event_type="UserLoggedInEvent",
                security_enhanced=True
            )
            
        except Exception as e:
            # Log event publishing failure but don't fail authentication
            self._logger.error(
                "Failed to publish login event with security context",
                user_id=user.id,
                error=str(e),
                correlation_id=correlation_id,
                security_enhanced=True
            )
    
    def _sanitize_user_agent(self, user_agent: str) -> str:
        """Sanitize user agent string for secure logging.
        
        Args:
            user_agent: Raw user agent string
            
        Returns:
            str: Sanitized user agent string safe for logging
        """
        if not user_agent:
            return "unknown"
        
        # Limit length and remove potentially harmful characters
        sanitized = user_agent[:200]  # Reasonable length limit
        # Remove control characters and other potentially harmful content
        sanitized = ''.join(char for char in sanitized if char.isprintable())
        
        return sanitized or "sanitized"
    
    def _analyze_risk_indicators(
        self,
        username: Username,
        ip_address: str,
        user_agent: str
    ) -> list[str]:
        """Analyze risk indicators for authentication attempt.
        
        Args:
            username: Username being attempted
            ip_address: Client IP address
            user_agent: User agent string
            
        Returns:
            list[str]: List of risk indicators detected
        """
        risk_indicators = []
        
        # Check for suspicious patterns
        username_str = str(username).lower()
        if any(pattern in username_str for pattern in ['admin', 'root', 'test', 'guest']):
            risk_indicators.append("suspicious_username")
        
        # Check for common automation patterns
        if user_agent and any(pattern in user_agent.lower() for pattern in ['bot', 'crawler', 'script']):
            risk_indicators.append("automated_user_agent")
        
        # Check for empty or missing user agent
        if not user_agent or len(user_agent.strip()) < 10:
            risk_indicators.append("minimal_user_agent")
        
        return risk_indicators