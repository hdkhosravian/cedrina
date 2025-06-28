"""API v1 router configuration.
"""

from fastapi import APIRouter

from .admin.policies import router as admin_policies_router
from .auth import router as auth_router
from .health import router as health_router
from .metrics import router as metrics_router

api_router = APIRouter()

api_router.include_router(health_router, prefix="/health", tags=["health"])
api_router.include_router(metrics_router, prefix="/metrics", tags=["metrics"])
api_router.include_router(auth_router, tags=["auth"])
api_router.include_router(admin_policies_router, prefix="/admin", tags=["admin", "policies"])
