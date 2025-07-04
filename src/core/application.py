"""Application factory for creating and configuring the FastAPI application.

This module provides a factory function to create a properly configured FastAPI application
with all necessary middleware, exception handlers, and routers registered.
"""

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from src.adapters.api.v1 import api_router
from src.adapters.api.v1.docs import router as docs_router
from src.adapters.websockets import ws_router
from src.core.config.settings import settings
from src.core.lifecycle import create_lifespan_manager
from src.core.middleware import configure_middleware
from src.core.handlers import register_exception_handlers
from src.utils.i18n import get_translated_message


def create_application() -> FastAPI:
    """Create and configure the FastAPI application.
    
    This factory function creates a FastAPI application with all necessary
    configuration, middleware, exception handlers, and routers.
    
    Returns:
        FastAPI: The configured FastAPI application instance
    """
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description=getattr(
            settings, "DESCRIPTION", "A FastAPI application with role-based access control."
        ),
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=create_lifespan_manager(),
        default_response_class=JSONResponse,
        default_response_description=get_translated_message(
            "successful_response", settings.DEFAULT_LANGUAGE
        ),
    )
    
    # Configure middleware
    configure_middleware(app)
    
    # Register exception handlers
    register_exception_handlers(app)
    
    # Include routers
    app.include_router(api_router, prefix="/api/v1")
    app.include_router(ws_router, prefix="/ws")
    app.include_router(docs_router)
    
    return app 