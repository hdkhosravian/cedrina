from redis.asyncio import Redis
from src.core.config.settings import settings

async def get_redis() -> Redis:
    """
    Provides an asynchronous Redis client.

    This function creates and yields a Redis client based on the application's
    settings. It is intended to be used as a FastAPI dependency.

    Yields:
        Redis: An asynchronous Redis client instance.
    """
    redis = Redis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    try:
        yield redis
    finally:
        await redis.aclose() 