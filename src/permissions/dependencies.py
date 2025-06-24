"""
Casbin Permission Dependencies Module

This module defines FastAPI dependencies for checking permissions using Casbin, an advanced access control library.
These dependencies are used to protect API endpoints by ensuring that only authorized users with the appropriate
roles can access specific resources or perform certain actions.

The permission check process involves retrieving the current user's role from the authentication context and
using the Casbin enforcer to evaluate whether the role has permission to access a given resource with a specific
action (e.g., GET, POST). If the permission check fails, an HTTP 403 Forbidden exception is raised to prevent
unauthorized access.

**Security Note**: Permission checks are critical to prevent unauthorized access (OWASP A01:2021 - Broken Access
Control). Ensure that roles are securely assigned and validated during authentication to prevent role spoofing.
Permission denial events are logged for audit purposes to detect potential brute-force or privilege escalation
attempts. Always use least privilege principles when defining policies.

Key Components:
    - check_permission: A factory function that creates a FastAPI dependency to enforce permissions for a specific
      resource and action, using the user's role from the authentication system.

This module ensures that access control logic is decoupled from business logic, adhering to the Single
Responsibility Principle and making the system easier to maintain and extend.
"""

from fastapi import Depends, HTTPException, status, Request
import casbin
import logging

from src.core.dependencies.auth import get_current_user
from src.domain.entities.user import User
from .enforcer import get_enforcer
from src.core.exceptions import PermissionError
from src.utils.i18n import get_translated_message

# Configure logging for permission denial events
logger = logging.getLogger(__name__)

def check_permission(resource: str, action: str) -> callable:
    """
    Create a dependency to check if the current user has permission to access a resource.

    This function generates a FastAPI dependency that evaluates whether the current user,
    based on their role, is allowed to perform the specified action on the given resource.
    It uses the Casbin enforcer to make this determination based on the loaded policies.

    If the user does not have the required permission, an HTTP 403 Forbidden exception is
    raised with a detailed error message, preventing unauthorized access to protected endpoints.
    Denial events are logged for security auditing.

    Args:
        resource (str): The resource (endpoint) to check access for (e.g., '/health').
        action (str): The action (e.g., 'GET', 'POST') to check permission for.

    Returns:
        callable: A FastAPI dependency function that performs the permission check.

    Example:
        To protect an endpoint for GET access to '/health':
        `@router.get('/health', dependencies=[Depends(check_permission('/health', 'GET'))])`
    """
    async def permission_dependency(
        request: Request,
        current_user: User = Depends(get_current_user),
        enforcer: casbin.Enforcer = Depends(get_enforcer)
    ) -> None:
        """
        The actual dependency that will be executed by FastAPI.

        Args:
            request (Request): The incoming HTTP request, used to access request context like language.
            current_user (User): The authenticated user object, injected by the auth dependency.
            enforcer (casbin.Enforcer): The Casbin enforcer instance for policy evaluation.

        Raises:
            PermissionError: If the user has no role or permission is denied for the action/resource.
        """
        locale = request.state.language
        if current_user.role is None:
            message = get_translated_message("user_has_no_role", locale)
            logger.warning(f"Permission denied: User {current_user.id} has no role assigned")
            raise PermissionError(message)
        
        user_role = current_user.role.value
        result = enforcer.enforce(user_role, resource, action)
        if hasattr(result, "__await__"):
            result = await result
        if not result:
            message = get_translated_message("permission_denied_for_action", locale).format(
                role=user_role, action=action, resource=resource
            )
            logger.warning(f"Permission denied: Role {user_role} cannot {action} on {resource}")
            raise PermissionError(message)
    return permission_dependency 