from __future__ import annotations

"""Async database utilities.

This module complements ``src.infrastructure.database.database`` by providing
*async* SQLAlchemy utilities required by the new authentication endpoints.

The synchronous engine is still kept for background jobs and test-suites that
expect it, but the authentication layer **requires** an ``AsyncSession`` so
we expose a *minimal* helper here without touching the existing code-path.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel
from sqlalchemy.engine import make_url
import urllib.parse as urlparse

from src.core.config.settings import settings

# ---------------------------------------------------------------------------
# Engine / session-factory
# ---------------------------------------------------------------------------

# Construct the async database URL
async_url = settings.DATABASE_URL.replace('postgresql+psycopg2', 'postgresql+asyncpg')
# Strip sslmode from the URL if present, as asyncpg handles SSL differently
parsed = urlparse.urlparse(async_url)
query = dict(urlparse.parse_qsl(parsed.query))
query.pop('sslmode', None)
new_query = urlparse.urlencode(query)
parsed = parsed._replace(query=new_query)
cleaned_url = urlparse.urlunparse(parsed)
url = make_url(cleaned_url)
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
    """FastAPI dependency that yields an *AsyncSession*.

    The helper mirrors the behaviour of :pyfunc:`src.infrastructure.database.database.get_db`.
    It automatically rolls-back the transaction if an exception bubbles up.
    """

    async with AsyncSessionFactory() as session:  # pragma: no cover – boilerplate
        try:
            yield session
        except Exception:  # noqa: BLE001 – Any DB error must trigger rollback
            await session.rollback()
            raise
        finally:
            await session.close()


async def create_async_db_and_tables() -> None:  # noqa: D401
    """Create tables using the *async* engine (mainly for test-suites)."""

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all) 