"""
Casbin Permission Dependencies Module

This module defines FastAPI dependencies for checking permissions using Casbin, an advanced access control library.
These dependencies are used to protect API endpoints by ensuring that only authorized users with the appropriate
roles can access specific resources or perform certain actions.

The permission check process involves retrieving the current user's role from the authentication context and
using the Casbin enforcer to evaluate whether the role has permission to access a given resource with a specific
action (e.g., GET, POST). If the permission check fails, an HTTP 403 Forbidden exception is raised to prevent
unauthorized access.

Key Components:
    - check_permission: A factory function that creates a FastAPI dependency to enforce permissions for a specific
      resource and action, using the user's role from the authentication system.

This module ensures that access control logic is decoupled from business logic, adhering to the Single
Responsibility Principle and making the system easier to maintain and extend.
"""

from fastapi import Depends, HTTPException, status, Request
import casbin

from src.core.dependencies.auth import get_current_user
from src.domain.entities.user import User
from .enforcer import get_enforcer
from src.core.exceptions import PermissionError
from src.utils.i18n import get_translated_message

def check_permission(resource: str, action: str):
    """
    Create a dependency to check if the current user has permission to access a resource.

    This function generates a FastAPI dependency that evaluates whether the current user,
    based on their role, is allowed to perform the specified action on the given resource.
    It uses the Casbin enforcer to make this determination based on the loaded policies.

    If the user does not have the required permission, an HTTP 403 Forbidden exception is
    raised with a detailed error message, preventing unauthorized access to protected endpoints.

    Args:
        resource (str): The resource (endpoint) to check access for (e.g., '/health').
        action (str): The action (e.g., 'GET', 'POST') to check permission for.

    Returns:
        callable: A FastAPI dependency function that performs the permission check.
    """
    async def permission_dependency(
        request: Request,
        current_user: User = Depends(get_current_user),
        enforcer: casbin.Enforcer = Depends(get_enforcer)
    ):
        """
        The actual dependency that will be executed by FastAPI.
        """
        locale = request.state.language
        if current_user.role is None:
            message = get_translated_message("user_has_no_role", locale)
            raise PermissionError(message)
        
        user_role = current_user.role.value
        result = enforcer.enforce(user_role, resource, action)
        if hasattr(result, "__await__"):
            result = await result
        if not result:
            message = get_translated_message("permission_denied_for_action", locale).format(
                role=user_role, action=action, resource=resource
            )
            raise PermissionError(message)
    return permission_dependency 