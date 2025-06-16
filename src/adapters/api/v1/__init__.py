"""
API v1 router configuration.
"""
from fastapi import APIRouter
from .health import router as health_router
from .metrics import router as metrics_router

api_router = APIRouter()

api_router.include_router(health_router, prefix="/health", tags=["health"])
api_router.include_router(metrics_router, prefix="/metrics", tags=["metrics"])