from core.config.settings import settings
from core.logging import logger
from utils.i18n import get_translated_message
from fastapi import APIRouter, Request, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
from infrastructure.database.database import check_database_health
import redis
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import httpx
import asyncio
from datetime import datetime, timezone

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
        redis_client = redis.Redis.from_url(
            settings.REDIS_URL,
            decode_responses=True
        )
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

@router.get("/", response_model=HealthResponse)
async def health_check(request: Request):
    """
    Comprehensive health check endpoint that verifies all service dependencies.
    """
    language = request.state.language
    status_message = get_translated_message("health_status_ok", language)
    
    # Run health checks concurrently
    redis_health, db_health = await asyncio.gather(
        check_redis_health(),
        check_database_health_async()
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
        services={
            "redis": redis_health,
            "database": db_health
        },
        timestamp=datetime.now(timezone.utc)
    )