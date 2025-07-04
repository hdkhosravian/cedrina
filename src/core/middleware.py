"""Middleware configuration for the FastAPI application.

This module handles the configuration and registration of all middleware
components including CORS, rate limiting, and language handling.
"""

import i18n
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi.middleware import SlowAPIMiddleware

from src.core.config.settings import settings
from src.utils.i18n import get_request_language


def configure_middleware(app: FastAPI) -> None:
    """Configure all middleware for the FastAPI application.
    
    Args:
        app (FastAPI): The FastAPI application instance
    """
    # CORS middleware configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Rate limiting middleware
    app.add_middleware(SlowAPIMiddleware)

    # Language middleware
    app.middleware("http")(set_language_middleware)


async def set_language_middleware(request: Request, call_next):
    """Middleware for handling language preferences in requests.

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