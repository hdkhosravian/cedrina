"""Metrics endpoint for exposing application metrics.
"""

from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request

from src.core.config.settings import settings
from src.core.dependencies.auth import get_current_admin_user
from src.core.metrics import metrics_collector
from src.utils.i18n import get_translated_message

router = APIRouter()


@router.get("/", response_model=Dict[str, Any], dependencies=[Depends(get_current_admin_user)])
async def get_metrics(request: Request):
    """Get application metrics.

    This endpoint exposes various metrics including:
    - System metrics (CPU, memory, disk)
    - Application metrics (request counts, response times)
    - Database metrics (query counts, execution times)
    - Cache metrics (hit/miss rates)

    Access to this endpoint is restricted to users with the 'admin' role, enforced by the Casbin permission
    system to protect sensitive performance and operational data from unauthorized access.

    Args:
        request (Request): The incoming HTTP request object, used to determine the preferred language for
                           error messages.

    Returns:
        Dict[str, Any]: Collected metrics in a structured dictionary format, providing detailed insights into
                        system and application performance.

    Raises:
        HTTPException: If the user does not have the required permissions (HTTP 403 Forbidden), as determined
                       by the Casbin enforcer.
                       If not in debug mode, returns HTTP 403 with a message indicating restricted access.

    """
    if not settings.DEBUG:
        raise HTTPException(
            status_code=403,
            detail=get_translated_message("metrics_endpoint_debug_only", request.state.language),
        )

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics_collector.get_metrics(),
    }
