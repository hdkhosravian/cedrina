"""
Logging configuration module for structured logging.

This module configures the application's logging system using structlog.
It provides structured logging capabilities with JSON formatting for production
and human-readable console output for development.

The logging configuration includes:
- Timestamp formatting
- Log level inclusion
- JSON/Console output based on environment
- Context management
- Logger caching
"""

import structlog
from structlog.types import Processor

from src.core.config.settings import settings

def configure_logging(log_level: str = "INFO", json_logs: bool = False):
    """
    Configures the application's logging system.
    
    This function sets up structlog with:
    1. ISO format timestamps
    2. Log level inclusion
    3. JSON formatting for production (when LOG_JSON=True)
    4. Console formatting for development
    5. Dictionary-based context
    6. Standard library logger factory
    7. Bound logger for context management
    8. Logger caching for performance
    
    The configuration is based on the application settings and environment.
    """
    processors = [
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.processors.JSONRenderer() if settings.LOG_JSON else structlog.dev.ConsoleRenderer(),
    ]

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

# Create a singleton logger instance for the application
logger = structlog.get_logger()