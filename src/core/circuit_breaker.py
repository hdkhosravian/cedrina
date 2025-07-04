"""Circuit breaker implementation for external service calls.

This module provides a robust, asyncio-compatible circuit breaker to prevent
cascading failures when interacting with external services. It follows the classic
circuit breaker pattern with closed, open, and half-open states.
"""

import asyncio
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Coroutine, Optional, TypeVar

from core.logging import logger

# Type variable for the decorated function's return value
T = TypeVar("T")


class CircuitBreakerError(Exception):
    """Custom exception raised when the circuit breaker is open."""

    def __init__(self, breaker_name: str, message: str = None):
        self.breaker_name = breaker_name
        if message is None:
            message = f"Circuit breaker {breaker_name} is open"
        self.message = message
        super().__init__(self.message)


class CircuitBreaker:
    """Circuit breaker implementation for handling external service failures.

    This implementation follows the circuit breaker pattern to prevent cascading
    failures and provide graceful degradation when external services are unavailable.

    State Transitions:
    - CLOSED: All requests are allowed. If failures exceed `failure_threshold`,
      the state transitions to OPEN.
    - OPEN: All requests are blocked for `reset_timeout` seconds. After the
      timeout, the state transitions to HALF-OPEN.
    - HALF-OPEN: A limited number of trial requests are allowed. If a request
      succeeds, the state transitions to CLOSED. If it fails, it returns to OPEN.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        reset_timeout: int = 60,
        half_open_timeout: int = 5,
        name: str = "default",
    ):
        """Initializes the CircuitBreaker.

        Args:
            failure_threshold (int): The number of consecutive failures required
                to open the circuit.
            reset_timeout (int): The time in seconds to wait in the OPEN state
                before transitioning to HALF-OPEN.
            half_open_timeout (int): The time in seconds to wait in HALF-OPEN state
                before transitioning back to OPEN if no success occurs.
            name (str): The name of the circuit breaker, used for logging.
        """
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.half_open_timeout = half_open_timeout
        self.name = name

        self.failures = 0
        self.last_failure_time: Optional[datetime] = None
        self.state = "closed"  # Can be "closed", "open", or "half-open"
        self._lock = asyncio.Lock()

    async def __aenter__(self):
        """Enter the context manager, checking if the circuit is open."""
        if not await self._allow_request():
            raise CircuitBreakerError(self.name)
        return self

    async def __aexit__(self, exc_type, exc_val, traceback):
        """Exit the context manager, updating state based on outcome."""
        if exc_type:
            await self._record_failure()
        else:
            await self._record_success()

    @property
    def is_closed(self) -> bool:
        """Return True if the circuit is closed."""
        return self.state == "closed"

    @property
    def is_open(self) -> bool:
        """Return True if the circuit is open."""
        if self.state == "open":
            if self.last_failure_time and (
                datetime.now(timezone.utc) - self.last_failure_time
            ).total_seconds() > self.reset_timeout:
                self.state = "half-open"
                logger.info("Circuit breaker transitioning to half-open", breaker=self.name)
                return False
            return True
        return False

    async def _allow_request(self) -> bool:
        """Determine if a request should be allowed based on the current state."""
        async with self._lock:
            return not self.is_open

    async def _record_success(self) -> None:
        """Record a successful operation, closing the circuit if half-open."""
        async with self._lock:
            if self.state == "half-open":
                self.state = "closed"
                self.failures = 0
                self.last_failure_time = None
                logger.info("Circuit breaker closed after successful half-open call", breaker=self.name)
            self.failures = 0

    async def _record_failure(self) -> None:
        """Record a failure, opening the circuit if the threshold is reached."""
        async with self._lock:
            self.failures += 1
            self.last_failure_time = datetime.now(timezone.utc)
            if self.failures >= self.failure_threshold:
                if self.state != "open":
                    self.state = "open"
                    logger.warning(
                        "Circuit breaker opened due to failure threshold",
                        breaker=self.name,
                        failures=self.failures,
                    )

    async def execute(self, func: Callable[..., Coroutine[Any, Any, T]], *args: Any, **kwargs: Any) -> T:
        """Execute an async function with circuit breaker protection.

        Args:
            func: The async function to execute.
            *args: Positional arguments for the function.
            **kwargs: Keyword arguments for the function.

        Returns:
            The result of the function execution.

        Raises:
            CircuitBreakerError: If the circuit is open.
            Exception: Propagates exceptions from the executed function.
        """
        if not await self._allow_request():
            raise CircuitBreakerError(self.name)

        try:
            result = await func(*args, **kwargs)
            await self._record_success()
            return result
        except Exception as e:
            await self._record_failure()
            logger.error("Circuit breaker recorded failure", breaker=self.name, error=str(e))
            raise

    async def _update_state(self, success: bool) -> None:
        """Test helper to update the circuit breaker state based on success or failure.

        Args:
            success (bool): True if the operation succeeded, False if it failed.
        """
        if success:
            await self._record_success()
        else:
            await self._record_failure()

    async def _check_state(self) -> bool:
        """Test helper to check if a request is allowed (for test introspection)."""
        return await self._allow_request()


def circuit_breaker(
    failure_threshold: int = 5,
    reset_timeout: int = 60,
    half_open_timeout: int = 5,
    name: Optional[str] = None,
) -> Callable[[Callable[..., Coroutine[Any, Any, T]]], Callable[..., Coroutine[Any, Any, T]]]:
    """Decorator to apply circuit breaker pattern to an async function.

    This decorator wraps an async function with a CircuitBreaker instance,
    providing automatic protection against repeated failures.

    Args:
        failure_threshold (int): Number of failures before opening the circuit.
        reset_timeout (int): Time in seconds before transitioning to half-open.
        half_open_timeout (int): Time in seconds to wait in HALF-OPEN state before returning to OPEN.
        name (Optional[str]): A name for the circuit breaker. If not provided,
            the function's name is used.

    Returns:
        A decorator that wraps an async function with circuit breaker logic.
    """

    def decorator(
        func: Callable[..., Coroutine[Any, Any, T]]
    ) -> Callable[..., Coroutine[Any, Any, T]]:
        breaker_name = name or func.__name__
        breaker = CircuitBreaker(
            failure_threshold=failure_threshold,
            reset_timeout=reset_timeout,
            half_open_timeout=half_open_timeout,
            name=breaker_name,
        )

        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            return await breaker.execute(func, *args, **kwargs)

        return wrapper

    return decorator
