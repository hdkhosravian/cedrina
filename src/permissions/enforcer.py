"""Casbin Enforcer Module

This module initializes the Casbin enforcer, which is the core component responsible for evaluating and enforcing
access control policies in the application. The enforcer uses a model configuration and a set of policies to
determine whether a subject (e.g., a user or role) is allowed to perform a specific action on a given resource.

Casbin supports multiple access control models such as Role-Based Access Control (RBAC), Attribute-Based Access
Control (ABAC), and more, making it highly flexible for complex permission requirements. In this application, it
is primarily used for RBAC to restrict access to certain API endpoints based on user roles.

The enforcer is initialized as a singleton instance to ensure consistent policy enforcement across the application.
It loads the model and policy files defined in the config module during startup.

**Security Note**: The enforcer must be initialized with trusted model and policy files to prevent policy tampering
(OWASP A01:2021 - Broken Access Control). Ensure that policy updates are audited and validated to prevent
unauthorized access. Consider using a persistent storage adapter for production environments to maintain policy
integrity across restarts.

Functions:
    get_enforcer: Returns the initialized Casbin enforcer instance for use in permission checks.
"""

import logging
import os
import warnings

import casbin
from casbin_sqlalchemy_adapter import Adapter as SQLAlchemyAdapter

from src.core.config.settings import settings

from .redis_watcher import RedisWatcher

# Suppress SQLAlchemy deprecation warning from casbin_sqlalchemy_adapter
warnings.filterwarnings("ignore", category=DeprecationWarning, module="casbin_sqlalchemy_adapter")

logger = logging.getLogger(__name__)

# Global enforcer instance for singleton pattern
_enforcer = None


def get_enforcer() -> casbin.Enforcer:
    """Initialize and return the Casbin enforcer with the configured model and adapter.

    This function sets up the access control system using Casbin, a powerful and efficient open-source
    access control library. It loads the model configuration from a file and connects to the database
    using an adapter for persistent policy storage. If the database adapter fails (e.g., due to
    connectivity issues), it falls back to a file-based adapter using a CSV file for policies.

    **Security Note**: The enforcer is cached to prevent reinitialization on every request, which would
    degrade performance. Ensure that the model and policy files are protected from unauthorized
    modifications to prevent policy tampering.

    Returns:
        casbin.Enforcer: The initialized Casbin enforcer instance for access control decisions.

    Example:
        To check if a user has permission:
        `enforcer = get_enforcer(); enforcer.enforce('user_role', '/resource', 'GET', 'dept', 'loc', 'time')`

    """
    global _enforcer
    if _enforcer is not None:
        return _enforcer

    model_path = os.path.join(os.path.dirname(__file__), "model.conf")
    if not os.path.exists(model_path):
        logger.error(f"Casbin model file not found at {model_path}")
        raise FileNotFoundError(f"Casbin model file not found at {model_path}")

    try:
        from src.infrastructure.database import engine

        adapter = SQLAlchemyAdapter(engine)
        logger.info("Casbin using database adapter for policy storage")
    except Exception as e:
        logger.warning(f"Failed to initialize database adapter: {e}, falling back to file adapter")
        policy_path = os.path.join(os.path.dirname(__file__), "policy.csv")
        if not os.path.exists(policy_path):
            logger.error(f"Casbin policy file not found at {policy_path}")
            raise FileNotFoundError(f"Casbin policy file not found at {policy_path}")
        adapter = casbin.persist.adapters.FileAdapter(policy_path)

    _enforcer = casbin.Enforcer(model_path, adapter, True)

    # Initialize Redis watcher for policy synchronization across instances
    try:
        # Extract Redis connection details from settings
        redis_host = settings.REDIS_HOST
        redis_port = settings.REDIS_PORT
        redis_password = (
            settings.REDIS_PASSWORD.get_secret_value() if settings.REDIS_PASSWORD else None
        )

        # Configure Redis watcher for policy synchronization
        watcher_config = {
            "host": redis_host,
            "port": redis_port,
            "db": 1,  # Use database 1 for Casbin to avoid conflicts with other Redis usage
        }

        if redis_password:
            watcher_config["password"] = redis_password

        watcher = RedisWatcher(**watcher_config)
        _enforcer.set_watcher(watcher)

        # Set update callback to reload policies when they change
        def update_callback():
            logger.info("Policy update detected via Redis watcher, reloading policies")
            _enforcer.load_policy()

        watcher.set_update_callback(update_callback)
        logger.info("Redis watcher configured successfully for policy synchronization")

    except Exception as e:
        logger.warning(
            f"Failed to initialize Redis watcher: {e}. "
            f"Policy synchronization across instances will not be available. "
            f"This is acceptable for single-instance deployments."
        )

    logger.info("Casbin enforcer initialized successfully")
    return _enforcer
