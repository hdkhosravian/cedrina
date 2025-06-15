"""
Main application entry point for the FastAPI application.

This module serves as the central configuration and initialization point for the application.
It sets up the FastAPI application, configures middleware, initializes database connections,
and manages application lifecycle events.

Key responsibilities:
- Application initialization and configuration
- Middleware setup (CORS, language)
- Database connection management
- API and WebSocket router registration
- Application lifecycle management (startup/shutdown)
"""

import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from src.core.config.settings import settings
from src.core.logging import configure_logging, logger
from src.adapters.api.v1 import api_router
from src.adapters.websockets import ws_router
from src.utils.i18n import setup_i18n, get_request_language
import i18n
from src.infrastructure.database import create_db_and_tables, check_database_health
from contextlib import asynccontextmanager
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware

# Load environment variables
load_dotenv(override=True)

# Configure logging
configure_logging(log_level=settings.LOG_LEVEL, json_logs=settings.LOG_JSON)

# Setup i18n
setup_i18n()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager that handles startup and shutdown events.
    
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
    
    yield
    
    # Shutdown
    logger.info("application_shutdown", env=settings.APP_ENV)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=getattr(settings, 'DESCRIPTION', 'A FastAPI application with role-based access control.'),
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan,
)

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def set_language_middleware(request: Request, call_next):
    """
    Middleware for handling language preferences in requests.
    
    This middleware:
    1. Extracts language preference from request headers or query parameters
    2. Sets the language for the current request
    3. Adds language information to response headers
    
    Args:
        request (Request): The incoming request
        call_next: The next middleware or route handler
        
    Returns:
        Response: The response with language headers
    """
    lang = get_request_language(request)
    i18n.set("locale", lang)
    request.state.language = lang
    response = await call_next(request)
    response.headers["Content-Language"] = lang
    return response

# Include API and WebSocket routers
app.include_router(api_router, prefix="/api/v1")
app.include_router(ws_router, prefix="/ws")