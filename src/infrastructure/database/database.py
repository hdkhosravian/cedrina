"""
Synchronous Database Connection Module

This module manages synchronous database connections using SQLModel and SQLAlchemy for the application.
It provides utilities for session management, health checks, and query logging. Synchronous operations
are typically used for background jobs or test suites that do not require asynchronous database access.

The database engine is configured with settings for connection pooling, timeouts, and SSL mode to ensure
reliable and secure connectivity to the PostgreSQL database.

**Security Note**: Ensure that the database connection URL (DATABASE_URL) uses SSL/TLS (via sslmode) for
secure communication over untrusted networks to prevent data interception (OWASP A02:2021 - Cryptographic
Failures). Avoid logging sensitive information such as connection strings or credentials to prevent
information disclosure (OWASP A09:2021 - Security Logging and Monitoring Failures). Use least privilege
principles for database accounts to minimize damage in case of compromise.

Key Components:
    - engine: The SQLAlchemy engine configured for synchronous database connections.
    - get_db_session: A context manager for creating database sessions with logging.
    - get_db: A FastAPI dependency for injecting database sessions.
    - log_query_execution: Utility to log query details without sensitive data.
    - check_database_health: Function to verify database connectivity with retry logic.
    - create_db_and_tables: Function to create database tables on startup.
"""

from sqlmodel import create_engine, SQLModel, Session
from sqlalchemy.sql import text
from src.core.config.settings import settings
from src.core.logging import logger
from sqlalchemy.exc import OperationalError
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import time
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from contextlib import contextmanager
from typing import Generator, Any, Optional
import json

# Create the engine with advanced PostgreSQL settings
engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=settings.POSTGRES_POOL_SIZE,
    max_overflow=settings.POSTGRES_MAX_OVERFLOW,
    pool_timeout=settings.POSTGRES_POOL_TIMEOUT,
    pool_pre_ping=True,  # Check connection health before use
    connect_args={"sslmode": settings.POSTGRES_SSL_MODE}
)

@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """
    Context manager for database sessions with logging.
    
    Yields:
        Session: A database session
        
    Raises:
        Exception: If session creation fails
    """
    session = None
    start_time = time.time()
    try:
        session = Session(engine)
        logger.debug(
            "database_session_created",
            pool_size=engine.pool.size(),
            checked_in=engine.pool.checkedin(),
            checked_out=engine.pool.checkedout()
        )
        yield session
    finally:
        if session:
            session.close()
            execution_time = time.time() - start_time
            logger.debug(
                "database_session_closed",
                execution_time=execution_time,
                pool_size=engine.pool.size(),
                checked_in=engine.pool.checkedin(),
                checked_out=engine.pool.checkedout()
            )

def get_db() -> Generator[Session, None, None]:
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
    with get_db_session() as session:
        try:
            yield session
        except Exception:
            session.rollback()
            raise

def log_query_execution(
    query: str,
    params: Optional[dict] = None,
    execution_time: float = 0.0,
    error: Optional[Exception] = None
) -> None:
    """
    Log database query execution details.

    This function logs details about database queries for debugging and monitoring purposes.
    It ensures that sensitive data like credentials or connection strings are not logged.

    **Security Note**: Avoid including sensitive data in query parameters or error messages
to prevent information disclosure (OWASP A09:2021 - Security Logging and Monitoring Failures).
    
    Args:
        query (str): The SQL query executed.
        params (Optional[dict]): Query parameters, if any. Ensure no sensitive data is included.
        execution_time (float): Time taken to execute the query in seconds.
        error (Optional[Exception]): Any error that occurred during execution.
    """
    log_data = {
        "query": query,
        "params": params,
        "execution_time": execution_time,
        "error": str(error) if error else None
    }
    
    if error:
        logger.error("database_query_error", **log_data)
    else:
        logger.debug("database_query_executed", **log_data)

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type(OperationalError)
)
def check_database_health() -> bool:
    """
    Performs a health check on the database connection.
    
    This function attempts to execute a simple query to verify database connectivity
    and responsiveness. It's used during application startup and can be used for
    periodic health checks.

    **Security Note**: Ensure health check failures are logged without exposing
    sensitive connection details to prevent information disclosure.
    
    Returns:
        bool: True if database is healthy and responsive, False otherwise.
    """
    start_time = time.time()
    try:
        with get_db_session() as session:
            result = session.exec(text("SELECT 1"))
            execution_time = time.time() - start_time
            logger.info(
                "database_health_check_success",
                execution_time=execution_time,
                pool_size=engine.pool.size()
            )
            return True
    except Exception as e:
        execution_time = time.time() - start_time
        logger.error(
            "database_health_check_failed",
            error=str(e),
            execution_time=execution_time,
            pool_size=engine.pool.size()
        )
        return False

def create_db_and_tables() -> None:
    """
    Creates database tables with logging.
    """
    start_time = time.time()
    SQLModel.metadata.create_all(engine)
    execution_time = time.time() - start_time
    logger.info(
        "database_tables_created",
        execution_time=execution_time,
        tables=list(SQLModel.metadata.tables.keys())
    )