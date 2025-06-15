"""
Metrics collection module for monitoring application performance and health.
"""
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import time
from core.logging import logger
from core.config.settings import settings
import psutil
import asyncio
from functools import wraps
import json

class MetricsCollector:
    """
    Collects and manages application metrics.
    
    This class provides functionality for collecting various metrics including:
    - System metrics (CPU, memory, disk)
    - Application metrics (request counts, response times)
    - Database metrics (query counts, execution times)
    - Cache metrics (hit/miss rates)
    """
    
    def __init__(self):
        self._metrics: Dict[str, Any] = {
            "system": {},
            "application": {},
            "database": {},
            "cache": {}
        }
        self._start_time = datetime.now(timezone.utc)
    
    def collect_system_metrics(self) -> Dict[str, Any]:
        """Collect system-level metrics."""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            metrics = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_used": memory.used,
                "memory_total": memory.total,
                "disk_percent": disk.percent,
                "disk_used": disk.used,
                "disk_total": disk.total,
                "uptime": (datetime.now(timezone.utc) - self._start_time).total_seconds()
            }
            
            self._metrics["system"] = metrics
            return metrics
        except Exception as e:
            logger.error("metrics_collection_error", error=str(e))
            return {}
    
    def record_request_metric(
        self,
        endpoint: str,
        method: str,
        status_code: int,
        duration: float
    ) -> None:
        """Record HTTP request metrics."""
        if "requests" not in self._metrics["application"]:
            self._metrics["application"]["requests"] = {}
        
        key = f"{method}:{endpoint}"
        if key not in self._metrics["application"]["requests"]:
            self._metrics["application"]["requests"][key] = {
                "count": 0,
                "total_duration": 0,
                "status_codes": {}
            }
        
        self._metrics["application"]["requests"][key]["count"] += 1
        self._metrics["application"]["requests"][key]["total_duration"] += duration
        self._metrics["application"]["requests"][key]["status_codes"][str(status_code)] = \
            self._metrics["application"]["requests"][key]["status_codes"].get(str(status_code), 0) + 1
    
    def record_database_metric(
        self,
        operation: str,
        duration: float,
        success: bool
    ) -> None:
        """Record database operation metrics."""
        if "operations" not in self._metrics["database"]:
            self._metrics["database"]["operations"] = {}
        
        if operation not in self._metrics["database"]["operations"]:
            self._metrics["database"]["operations"][operation] = {
                "count": 0,
                "total_duration": 0,
                "success_count": 0,
                "error_count": 0
            }
        
        self._metrics["database"]["operations"][operation]["count"] += 1
        self._metrics["database"]["operations"][operation]["total_duration"] += duration
        if success:
            self._metrics["database"]["operations"][operation]["success_count"] += 1
        else:
            self._metrics["database"]["operations"][operation]["error_count"] += 1
    
    def record_cache_metric(
        self,
        operation: str,
        hit: bool
    ) -> None:
        """Record cache operation metrics."""
        if "operations" not in self._metrics["cache"]:
            self._metrics["cache"]["operations"] = {}
        
        if operation not in self._metrics["cache"]["operations"]:
            self._metrics["cache"]["operations"][operation] = {
                "hits": 0,
                "misses": 0
            }
        
        if hit:
            self._metrics["cache"]["operations"][operation]["hits"] += 1
        else:
            self._metrics["cache"]["operations"][operation]["misses"] += 1
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get all collected metrics."""
        self.collect_system_metrics()  # Update system metrics
        return self._metrics
    
    def reset_metrics(self) -> None:
        """Reset all metrics to initial state."""
        self._metrics = {
            "system": {},
            "application": {},
            "database": {},
            "cache": {}
        }
        self._start_time = datetime.now(timezone.utc)

# Global metrics collector instance
metrics_collector = MetricsCollector()

def record_metric(metric_type: str):
    """
    Decorator for recording metrics for functions.
    
    Args:
        metric_type: Type of metric to record (e.g., 'database', 'cache')
    """
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                
                if metric_type == "database":
                    metrics_collector.record_database_metric(
                        func.__name__,
                        duration,
                        True
                    )
                elif metric_type == "cache":
                    metrics_collector.record_cache_metric(
                        func.__name__,
                        True
                    )
                
                return result
            except Exception as e:
                duration = time.time() - start_time
                
                if metric_type == "database":
                    metrics_collector.record_database_metric(
                        func.__name__,
                        duration,
                        False
                    )
                
                raise
            finally:
                if settings.DEBUG:
                    logger.debug(
                        f"{metric_type}_operation_completed",
                        operation=func.__name__,
                        duration=duration
                    )
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                if metric_type == "database":
                    metrics_collector.record_database_metric(
                        func.__name__,
                        duration,
                        True
                    )
                elif metric_type == "cache":
                    metrics_collector.record_cache_metric(
                        func.__name__,
                        True
                    )
                
                return result
            except Exception as e:
                duration = time.time() - start_time
                
                if metric_type == "database":
                    metrics_collector.record_database_metric(
                        func.__name__,
                        duration,
                        False
                    )
                
                raise
            finally:
                if settings.DEBUG:
                    logger.debug(
                        f"{metric_type}_operation_completed",
                        operation=func.__name__,
                        duration=duration
                    )
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    
    return decorator 