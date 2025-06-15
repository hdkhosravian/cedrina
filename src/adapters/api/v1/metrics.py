"""
Metrics endpoint for exposing application metrics.
"""
from fastapi import APIRouter, Depends, HTTPException
from src.core.metrics import metrics_collector
from src.core.config.settings import settings
from typing import Dict, Any
from datetime import datetime, timezone

router = APIRouter()

@router.get("/", response_model=Dict[str, Any])
async def get_metrics():
    """
    Get application metrics.
    
    This endpoint exposes various metrics including:
    - System metrics (CPU, memory, disk)
    - Application metrics (request counts, response times)
    - Database metrics (query counts, execution times)
    - Cache metrics (hit/miss rates)
    
    Returns:
        Dict[str, Any]: Collected metrics
    """
    if not settings.DEBUG:
        raise HTTPException(
            status_code=403,
            detail="Metrics endpoint is only available in debug mode"
        )
    
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics_collector.get_metrics()
    } 