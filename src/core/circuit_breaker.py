"""Circuit breaker implementation for external service calls.
"""

import asyncio
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Optional

from core.logging import logger


class CircuitBreaker:
    """Circuit breaker implementation for handling external service failures.

    This implementation follows the circuit breaker pattern to prevent cascading
    failures and provide graceful degradation when external services are unavailable.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        reset_timeout: int = 60,
        half_open_timeout: int = 30,
        name: str = "default",
    ):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.half_open_timeout = half_open_timeout
        self.name = name

        self.failures = 0
        self.last_failure_time = datetime.now(timezone.utc)
        self.state = "closed"  # closed, open, half-open
        self._lock = asyncio.Lock()

    async def _update_state(self, success: bool) -> None:
        """Update circuit breaker state based on operation result."""
        async with self._lock:
            if success:
                if self.state == "half-open":
                    self.state = "closed"
                    self.failures = 0
                    self.last_failure_time = datetime.now(timezone.utc)
                    logger.info("circuit_breaker_closed", breaker=self.name, failures=self.failures)
            else:
                self.failures += 1
                self.last_failure_time = datetime.now(timezone.utc)

                if self.failures >= self.failure_threshold:
                    self.state = "open"
                    logger.warning(
                        "circuit_breaker_opened", breaker=self.name, failures=self.failures
                    )

    async def _check_state(self) -> bool:
        """Check if circuit breaker should allow the operation."""
        async with self._lock:
            if self.state == "closed":
                return True

            if self.state == "open":
                if (
                    datetime.now(timezone.utc) - self.last_failure_time
                ).total_seconds() > self.reset_timeout:
                    self.state = "half-open"
                    logger.info("circuit_breaker_half_open", breaker=self.name)
                    return True
                return False

            # half-open state
            return True

    async def execute(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """Execute the function with circuit breaker protection.

        Args:
            func: The function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function

        Returns:
            The result of the function execution

        Raises:
            Exception: If the circuit is open or the function fails

        """
        if not await self._check_state():
            raise Exception(f"Circuit breaker {self.name} is open")

        try:
            start_time = time.time()
            result = (
                await func(*args, **kwargs)
                if asyncio.iscoroutinefunction(func)
                else func(*args, **kwargs)
            )
            execution_time = time.time() - start_time

            await self._update_state(True)
            logger.debug(
                "circuit_breaker_success", breaker=self.name, execution_time=execution_time
            )
            return result

        except Exception as e:
            await self._update_state(False)
            logger.error("circuit_breaker_failure", breaker=self.name, error=str(e))
            raise


def circuit_breaker(
    failure_threshold: int = 5,
    reset_timeout: int = 60,
    half_open_timeout: int = 30,
    name: Optional[str] = None,
):
    """Decorator for applying circuit breaker pattern to functions.

    Args:
        failure_threshold: Number of failures before opening the circuit
        reset_timeout: Time in seconds before attempting to close the circuit
        half_open_timeout: Time in seconds in half-open state
        name: Optional name for the circuit breaker

    Returns:
        Decorated function with circuit breaker protection

    """

    def decorator(func: Callable) -> Callable:
        breaker = CircuitBreaker(
            failure_threshold=failure_threshold,
            reset_timeout=reset_timeout,
            half_open_timeout=half_open_timeout,
            name=name or func.__name__,
        )

        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            return await breaker.execute(func, *args, **kwargs)

        @wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            return asyncio.run(breaker.execute(func, *args, **kwargs))

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    return decorator
