from __future__ import annotations

"""
Asynchronous Database Utilities Module

This module provides asynchronous database utilities using SQLAlchemy's asyncio support, complementing
the synchronous utilities in 'database.py'. It is specifically designed for components like authentication
endpoints that require asynchronous database access for better performance and scalability in high-concurrency
environments.

The synchronous engine is retained for background jobs and test suites, but this module exposes minimal
helpers for async operations without altering existing synchronous code paths.

**Security Note**: Ensure that the database connection URL (DATABASE_URL) is configured for SSL/TLS when
connecting over untrusted networks to prevent data interception (OWASP A02:2021 - Cryptographic Failures).
Note that asyncpg handles SSL differently, and 'sslmode' is not directly supported in connect_args; it must
be specified in the URL if required. Avoid logging sensitive connection details to prevent information
disclosure (OWASP A09:2021 - Security Logging and Monitoring Failures). Use least privilege principles for
database accounts.

Key Components:
    - engine: The asynchronous SQLAlchemy engine for PostgreSQL connections.
    - AsyncSessionFactory: A factory for creating asynchronous database sessions.
    - get_async_db: A context manager dependency for yielding async sessions.
    - create_async_db_and_tables: Utility to create tables using the async engine.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
import logging

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel
from sqlalchemy.engine import make_url
import urllib.parse as urlparse

from src.core.config.settings import settings
from src.core.logging import logger

# Configure logging for async database events
logger = logging.getLogger(__name__)

# Construct the async database URL
def _build_async_url() -> str:
    """
    Build the asynchronous database URL with proper handling of SSL parameters.

    This function constructs the async database URL by replacing the driver with asyncpg
    and cleaning up query parameters like sslmode, which asyncpg handles differently.

    **Security Note**: Ensure SSL parameters are included in the URL if connecting over
    an untrusted network to prevent data interception.

    Returns:
        str: The cleaned asynchronous database URL.
    """
    async_url = settings.DATABASE_URL.replace('postgresql+psycopg2', 'postgresql+asyncpg')
    # Strip sslmode from the URL if present, as asyncpg handles SSL differently
    parsed = urlparse.urlparse(async_url)
    query = dict(urlparse.parse_qsl(parsed.query))
    query.pop('sslmode', None)
    new_query = urlparse.urlencode(query)
    parsed = parsed._replace(query=new_query)
    cleaned_url = urlparse.urlunparse(parsed)
    return cleaned_url

url = make_url(_build_async_url())
conn_params = {}
# asyncpg does not support sslmode in connect_args, it's handled in the URL if needed
engine = create_async_engine(
    url,
    echo=False,
    future=True,
    connect_args=conn_params
)

AsyncSessionFactory: sessionmaker[AsyncSession] = sessionmaker(  # type: ignore[type-arg]
    bind=engine, class_=AsyncSession, expire_on_commit=False
)


@asynccontextmanager
async def get_async_db() -> AsyncGenerator[AsyncSession, None]:  # noqa: D401
    """
    FastAPI dependency that yields an AsyncSession.

    This helper mirrors the behavior of 'get_db' from the synchronous database module.
    It automatically rolls back the transaction if an exception occurs and ensures proper
    session closure.

    **Security Note**: Avoid logging sensitive session details to prevent information disclosure.

    Yields:
        AsyncSession: An asynchronous database session for use in FastAPI routes.

    Example:
        To use this dependency in a FastAPI route:
        `@router.get('/data', dependencies=[Depends(get_async_db)])`
    """
    async with AsyncSessionFactory() as session:  # pragma: no cover – boilerplate
        logger.debug("Async database session created")
        try:
            yield session
        except Exception:  # noqa: BLE001 – Any DB error must trigger rollback
            await session.rollback()
            logger.error("Async database session rollback due to error")
            raise
        finally:
            await session.close()
            logger.debug("Async database session closed")


async def create_async_db_and_tables() -> None:  # noqa: D401
    """
    Create tables using the async engine (mainly for test suites).

    This function initializes database tables asynchronously, typically used during
test setup or application initialization when async operations are preferred.
    """
    logger.info("Creating async database tables")
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all) 
    logger.info("Async database tables created") 