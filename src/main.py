"""Main application entry point for the FastAPI application.

This module serves as the central entry point for the application.
It initializes the application and creates the FastAPI instance using
the application factory pattern.
"""

from src.core.application import create_application
from src.core.initialization import initialize_application

# Initialize the application
initialize_application()

# Create the FastAPI application
app = create_application()
