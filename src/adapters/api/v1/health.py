import asyncio
from datetime import datetime, timezone
from typing import Any, Dict

import redis
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from src.core.config.settings import settings
from src.core.dependencies.auth import get_current_admin_user
from src.core.logging import logger
from src.infrastructure.database.database import check_database_health
from src.utils.i18n import get_translated_message

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    env: str
    message: str
    services: Dict[str, Any]
    timestamp: datetime


async def check_redis_health() -> Dict[str, Any]:
    """Check Redis connection health."""
    try:
        redis_client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        redis_client.ping()
        return {"status": "healthy", "latency_ms": 0}  # Add latency measurement if needed
    except Exception as e:
        logger.error("redis_health_check_failed", error=str(e))
        return {"status": "unhealthy", "error": str(e)}


async def check_database_health_async() -> Dict[str, Any]:
    """Check database connection health."""
    try:
        is_healthy = check_database_health()
        return {"status": "healthy" if is_healthy else "unhealthy"}
    except Exception as e:
        logger.error("database_health_check_failed", error=str(e))
        return {"status": "unhealthy", "error": str(e)}


@router.get("/", response_model=HealthResponse, dependencies=[Depends(get_current_admin_user)])
async def health_check(request: Request):
    """Comprehensive health check endpoint that verifies all service dependencies.

    This endpoint checks the health of critical dependencies such as the database and Redis. It returns a detailed
    status report indicating whether the system is fully operational or in a degraded state. Access to this
    endpoint is restricted to users with the 'admin' role, enforced by the Casbin permission system to ensure
    sensitive system information is not exposed to unauthorized users.

    Args:
        request (Request): The incoming HTTP request object, used to determine the preferred language for
                           status messages.

    Returns:
        HealthResponse: A structured response containing the overall system status, a localized status message,
                        and detailed health information for each service (e.g., database, Redis).

    Raises:
        HTTPException: If the user does not have the required permissions (HTTP 403 Forbidden), as determined
                       by the Casbin enforcer.

    """
    language = request.state.language
    status_message = get_translated_message("system_operational", language)

    # Run health checks concurrently
    redis_health, db_health = await asyncio.gather(
        check_redis_health(), check_database_health_async()
    )

    # Determine overall health, considering test environment
    services_healthy = db_health["status"] == "healthy"
    if settings.APP_ENV != "test":
        services_healthy = services_healthy and redis_health["status"] == "healthy"

    overall_status = "ok" if services_healthy else "degraded"

    return HealthResponse(
        status=overall_status,
        env=settings.APP_ENV,
        message=status_message,
        services={"redis": redis_health, "database": db_health},
        timestamp=datetime.now(timezone.utc),
    )
