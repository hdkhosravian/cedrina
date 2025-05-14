import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from src.core.config.settings import settings
from src.core.logging import configure_logging, logger
from src.adapters.api.v1 import api_router
from src.adapters.websockets import ws_router
from src.utils.i18n import setup_i18n, get_request_language
import i18n

# Load environment variables
load_dotenv(override=True)

# Configure logging
configure_logging()

# Setup i18n
setup_i18n()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("application_startup", env=settings.APP_ENV, version=settings.VERSION)
    yield
    # Shutdown
    logger.info("application_shutdown", env=settings.APP_ENV)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    debug=settings.DEBUG,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Language middleware
@app.middleware("http")
async def set_language_middleware(request: Request, call_next):
    lang = get_request_language(request)
    i18n.set("locale", lang)
    request.state.language = lang
    response = await call_next(request)
    response.headers["Content-Language"] = lang
    return response

# Include routers
app.include_router(api_router, prefix="/api/v1")
app.include_router(ws_router, prefix="/ws")