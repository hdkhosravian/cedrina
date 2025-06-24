"""
Redis Connection Module

This module provides an asynchronous Redis client for use in the application, typically for caching,
session storage, or rate limiting. Redis is a high-performance, in-memory data store that supports
various data structures and is often used to improve application scalability and performance.

The Redis client is provided as a FastAPI dependency, ensuring proper resource management by
closing the connection after use. The connection is configured based on the application's settings.

**Security Note**: Ensure that the Redis connection URL (REDIS_URL) includes SSL/TLS parameters if
connecting over an insecure network to prevent data interception (OWASP A02:2021 - Cryptographic
Failures). Use strong passwords and restrict access to Redis instances to trusted clients only.
Avoid logging sensitive connection details (e.g., passwords) to prevent information disclosure
(OWASP A09:2021 - Security Logging and Monitoring Failures).

Functions:
    get_redis: A FastAPI dependency that yields an asynchronous Redis client instance.
"""

from redis.asyncio import Redis
import logging

from src.core.config.settings import settings

# Configure logging for Redis connection events
logger = logging.getLogger(__name__)

async def get_redis() -> Redis:
    """
    Provides an asynchronous Redis client.

    This function creates and yields a Redis client based on the application's
    settings. It is intended to be used as a FastAPI dependency, ensuring that
    the connection is properly closed after use.

    **Security Note**: Verify that the Redis URL in settings includes SSL/TLS
    parameters for secure communication if not on a trusted network. Ensure that
    connection credentials are securely managed and not exposed in logs.

    Yields:
        Redis: An asynchronous Redis client instance.

    Example:
        To use this dependency in a FastAPI route:
        `@router.get('/cache', dependencies=[Depends(get_redis)])`
    """
    redis = Redis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    logger.debug("Redis connection created")
    try:
        yield redis
    finally:
        await redis.aclose() 
        logger.debug("Redis connection closed") 