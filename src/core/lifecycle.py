"""Application lifecycle management.

This module handles application startup and shutdown events, ensuring proper
initialization and cleanup of application resources.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from src.core.config.settings import settings
from src.core.logging import logger
from src.core.rate_limiting.ratelimiter import get_limiter
from src.infrastructure.database import check_database_health, create_db_and_tables


def create_lifespan_manager():
    """Create the application lifespan manager.
    
    Returns:
        AsyncContextManager: The lifespan manager for the FastAPI application
    """
    
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Application lifespan manager that handles startup and shutdown events.

        This context manager ensures proper initialization and cleanup of application resources.
        It performs database health checks, creates necessary tables, and handles graceful shutdown.

        Args:
            app (FastAPI): The FastAPI application instance

        Raises:
            RuntimeError: If database is unavailable during startup
        """
        # Startup
        if not check_database_health():
            logger.error("database_unavailable_on_startup")
            raise RuntimeError("Database unavailable")
        create_db_and_tables()
        logger.info("application_startup", env=settings.APP_ENV, version=settings.VERSION)

        # Attach the limiter to the app state
        app.state.limiter = get_limiter()

        yield

        # Shutdown
        logger.info("application_shutdown", env=settings.APP_ENV)
    
    return lifespan 