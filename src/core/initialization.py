"""Application initialization and setup.

This module handles the initialization tasks required before the application starts,
including environment variable loading, logging configuration, and i18n setup.
"""

from dotenv import load_dotenv

from src.core.config.settings import settings
from src.core.logging import configure_logging
from src.utils.i18n import setup_i18n


def initialize_application() -> None:
    """Initialize the application with all necessary setup tasks.
    
    This function performs the following initialization tasks:
    1. Load environment variables
    2. Configure logging
    3. Setup internationalization (i18n)
    """
    # Load environment variables
    load_dotenv(override=True)

    # Configure logging
    configure_logging(log_level=settings.LOG_LEVEL, json_logs=settings.LOG_JSON)

    # Setup i18n
    setup_i18n() 