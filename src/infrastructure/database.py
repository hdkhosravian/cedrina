"""
Database infrastructure module for managing PostgreSQL connections and operations.

This module provides the core database functionality including:
- Database engine configuration with connection pooling
- Health check mechanisms
- Table creation with retry logic
- Session management
- Error handling and logging

The module uses SQLModel for ORM functionality and implements best practices for
database connection management in a production environment.
"""

from sqlmodel import create_engine, SQLModel, Session
from src.core.config.settings import settings
from src.core.logging import logger
from sqlalchemy.exc import OperationalError
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import time

# Create the engine with advanced PostgreSQL settings
engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=settings.POSTGRES_POOL_SIZE,
    max_overflow=settings.POSTGRES_MAX_OVERFLOW,
    pool_timeout=settings.POSTGRES_POOL_TIMEOUT,
    pool_pre_ping=True,  # Check connection health before use
)

def check_database_health() -> bool:
    """
    Performs a health check on the database connection.
    
    This function attempts to execute a simple query to verify database connectivity
    and responsiveness. It's used during application startup and can be used for
    periodic health checks.
    
    Returns:
        bool: True if database is healthy and responsive, False otherwise
    """
    try:
        with Session(engine) as session:
            session.exec("SELECT 1")
        return True
    except Exception as e:
        logger.error("database_health_check_failed", error=str(e))
        return False

@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type(OperationalError),
)
def create_db_and_tables():
    """
    Creates database tables with retry logic.
    
    This function attempts to create all database tables defined in SQLModel models.
    It implements retry logic to handle temporary connection issues or database
    unavailability. The retry mechanism uses exponential backoff.
    
    Raises:
        OperationalError: If database operations fail after all retry attempts
        Exception: For other unexpected errors during table creation
    """
    try:
        SQLModel.metadata.create_all(engine)
        logger.info("database_tables_created")
    except OperationalError as e:
        logger.warning("database_tables_creation_retry", error=str(e))
        raise
    except Exception as e:
        logger.error("database_tables_creation_failed", error=str(e))
        raise

def get_db():
    """
    Dependency for database sessions.
    
    This function provides a database session for FastAPI dependency injection.
    It ensures proper session management including:
    - Session creation
    - Error handling
    - Automatic rollback on errors
    - Session cleanup
    
    Yields:
        Session: A SQLModel database session
        
    Raises:
        Exception: Any database-related errors that occur during session usage
    """
    with Session(engine) as session:
        try:
            yield session
        except Exception as e:
            logger.error("database_session_error", error=str(e))
            session.rollback()
            raise
        finally:
            session.close()