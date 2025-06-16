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

from src.core.config.settings import settings

# ---------------------------------------------------------------------------
# Engine / session-factory
# ---------------------------------------------------------------------------

ASYNC_DATABASE_URL = settings.DATABASE_URL.replace("postgresql+psycopg2", "postgresql+asyncpg")

_engine = create_async_engine(
    ASYNC_DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=settings.POSTGRES_POOL_SIZE,
    max_overflow=settings.POSTGRES_MAX_OVERFLOW,
    pool_timeout=settings.POSTGRES_POOL_TIMEOUT,
    pool_pre_ping=True,
)

AsyncSessionFactory: sessionmaker[AsyncSession] = sessionmaker(  # type: ignore[type-arg]
    bind=_engine, class_=AsyncSession, expire_on_commit=False
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

    async with _engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all) 