import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

@pytest_asyncio.fixture
def db_session():
    """Provides a mocked asynchronous database session."""
    mock_session = AsyncMock(spec=AsyncSession)
    mock_session.exec = AsyncMock()
    mock_session.exec.return_value = AsyncMock()
    mock_session.exec.return_value.first = AsyncMock(return_value=None)
    mock_session.get = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()
    mock_session.refresh = AsyncMock()
    
    return mock_session

@pytest_asyncio.fixture
def redis_client():
    """Provides a mocked asynchronous Redis client."""
    mock_redis = AsyncMock(spec=Redis)
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.setex = AsyncMock()
    mock_redis.delete = AsyncMock()
    return mock_redis 