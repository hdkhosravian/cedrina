from __future__ import annotations

"""Lightweight sliding-window rate-limiter dependency.

This module *does not* introduce an external package dependency (e.g. slowapi)
so it works seamlessly in unit-tests where a real Redis instance is absent.  At
runtime it uses Redis for distributed accuracy; in *TEST_MODE* it falls back to
an in-process dictionary so the test-suite remains hermetic.
"""

from typing import Callable, Awaitable, Dict, Tuple
from time import time
from fastapi import Request, HTTPException, status, Depends
from redis.asyncio import Redis
from structlog import get_logger

from src.infrastructure.redis import get_redis
from src.core.config.settings import settings
from src.core.exceptions import RateLimitError

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# In-memory fallback store (PID-local) – only used in test-mode or when Redis
# is unreachable.  The value is a tuple ``(counter, window_start)``.
# ---------------------------------------------------------------------------

_memory_store: Dict[str, Tuple[int, float]] = {}


def _use_memory_backend() -> bool:  # noqa: D401
    """Determine whether to fall back to the in-memory backend."""

    return bool(getattr(settings, "TEST_MODE", False))


# ---------------------------------------------------------------------------
# Public helper – factory returning a FastAPI dependency
# ---------------------------------------------------------------------------

def rate_limit(times: int = 5, seconds: int = 60) -> Callable[[Request, Redis], Awaitable[None]]:  # noqa: D401
    """Return a FastAPI *dependency* that applies simple fixed-window limiting.

    Args:
        times: Maximum number of requests.
        seconds: Window size in seconds.
    """

    async def _dependency(
        request: Request, redis: Redis = Depends(get_redis)  # noqa: D401
    ) -> None:
        if not settings.RATE_LIMIT_ENABLED:
            return  # short-circuit if feature toggled off

        identifier = request.client.host or "unknown"
        # For credential-related endpoints we also include path to separate limits.
        key = f"rate:{identifier}:{request.url.path}"

        # ------------------------------------------------------------------
        # Distributed (Redis) branch
        # ------------------------------------------------------------------
        if not _use_memory_backend():
            try:
                current = await redis.incr(key)
                if current == 1:
                    await redis.expire(key, seconds)
                if current > times:
                    logger.warning(
                        "rate_limit_exceeded", ip=identifier, key=key, count=current
                    )
                    raise RateLimitError()
                return
            except Exception as exc:  # pragma: no cover – network issues
                logger.error("redis_rate_limit_failed", error=str(exc))
                # Fall through to memory fallback

        # ------------------------------------------------------------------
        # In-memory fallback branch (best-effort; per-process)
        # ------------------------------------------------------------------
        now = time()
        counter, start = _memory_store.get(key, (0, now))
        if now - start >= seconds:
            counter, start = 0, now  # reset window
        counter += 1
        _memory_store[key] = (counter, start)
        if counter > times:
            logger.warning("rate_limit_exceeded", ip=identifier, key=key, count=counter)
            raise RateLimitError()

    return _dependency 