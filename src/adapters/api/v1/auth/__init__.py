from __future__ import annotations

"""Authentication router package – bundles registration/login/OAuth endpoints."""

from fastapi import APIRouter

from .routes import register as register_route  # noqa: WPS433 – re-export via package
from .routes import login as login_route  # noqa: WPS433
from .routes import oauth as oauth_route  # noqa: WPS433
from .routes import logout as logout_route  # noqa: WPS433
from .routes import change_password as change_password_route  # noqa: WPS433

router = APIRouter(prefix="/auth", tags=["auth"])

# Delegate to sub-routers ----------------------------------------------------

router.include_router(register_route.router, prefix="/register")
router.include_router(login_route.router, prefix="/login")
router.include_router(oauth_route.router, prefix="/oauth")
router.include_router(logout_route.router, prefix="/logout")
router.include_router(change_password_route.router, prefix="/change-password")

__all__ = ["router"] 
