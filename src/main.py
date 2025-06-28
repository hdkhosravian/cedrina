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
from src.adapters.api.v1.docs import router as docs_router
from src.utils.i18n import setup_i18n, get_request_language, get_translated_message
import i18n
from src.infrastructure.database import create_db_and_tables, check_database_health
from contextlib import asynccontextmanager
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from src.core.exceptions import (
    AuthenticationError,
    PermissionError,
    DuplicateUserError,
    PasswordPolicyError,
    PasswordValidationError,
    InvalidOldPasswordError,
    PasswordReuseError,
    DatabaseError,
)
from src.core.handlers import (
    authentication_error_handler,
    permission_error_handler,
    rate_limit_exception_handler,
    duplicate_user_error_handler,
    password_policy_error_handler,
    password_validation_error_handler,
    invalid_old_password_error_handler,
    password_reuse_error_handler,
)
from src.core.ratelimiter import get_limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

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
    
    # Attach the limiter to the app state
    app.state.limiter = get_limiter()
    
    yield
    
    # Shutdown
    logger.info("application_shutdown", env=settings.APP_ENV)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=getattr(settings, 'DESCRIPTION', 'A FastAPI application with role-based access control.'),
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
    default_response_class=JSONResponse,
    default_response_description=get_translated_message("successful_response", settings.DEFAULT_LANGUAGE)
)

def database_error_handler(request, exc: DatabaseError):
    return JSONResponse(status_code=500, content={"detail": exc.message})

# Register custom exception handlers
app.add_exception_handler(RateLimitExceeded, rate_limit_exception_handler)
app.add_exception_handler(AuthenticationError, authentication_error_handler)
app.add_exception_handler(PermissionError, permission_error_handler)
app.add_exception_handler(DuplicateUserError, duplicate_user_error_handler)
app.add_exception_handler(PasswordPolicyError, password_policy_error_handler)
app.add_exception_handler(PasswordValidationError, password_validation_error_handler)
app.add_exception_handler(InvalidOldPasswordError, invalid_old_password_error_handler)
app.add_exception_handler(PasswordReuseError, password_reuse_error_handler)
app.add_exception_handler(DatabaseError, database_error_handler)

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add Middleware
app.add_middleware(SlowAPIMiddleware)

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
app.include_router(docs_router)