"""
Casbin Permission Dependencies Module

This module defines FastAPI dependencies for checking permissions using Casbin, an advanced access control library.
These dependencies are used to protect API endpoints by ensuring that only authorized users with the appropriate
roles can access specific resources or perform certain actions.

The permission check process involves retrieving the current user's role (from an authentication context) and
using the Casbin enforcer to evaluate whether the role has permission to access a given resource with a specific
action (e.g., GET, POST). If the permission check fails, an HTTP 403 Forbidden exception is raised to prevent
unauthorized access.

Key Components:
    - get_current_user_role: A placeholder function to retrieve the current user's role, which should be integrated
      with the application's authentication system.
    - check_permission: A factory function that creates a FastAPI dependency to enforce permissions for a specific
      resource and action.

This module ensures that access control logic is decoupled from business logic, adhering to the Single
Responsibility Principle and making the system easier to maintain and extend.
"""

from fastapi import Depends, HTTPException, status
from .enforcer import get_enforcer
import casbin

# Placeholder for getting current user role (to be integrated with auth system)
async def get_current_user_role() -> str:
    """
    Retrieve the current user's role from the authentication context.

    This is a placeholder function that must be replaced with actual logic to fetch the user's role, typically
    from a JWT token, session, or database query after user authentication. The role is used by the Casbin
    enforcer to evaluate access permissions.

    WARNING: This function currently returns 'admin' for demonstration purposes. This is a SECURITY RISK and
    MUST be replaced with proper role retrieval logic in a production environment. Failure to do so will grant
    admin access to all users, bypassing the permission system entirely.

    Returns:
        str: The role of the current user (e.g., 'admin', 'user').
    """
    # TODO: CRITICAL - Integrate with auth system to get the actual user role. Hardcoding 'admin' is a security vulnerability.
    return "admin"  # Replace with real user role retrieval IMMEDIATELY

def check_permission(resource: str, action: str):
    """
    Create a dependency to check if the current user has permission to access a resource.

    This function generates a FastAPI dependency that evaluates whether the current user, based on their role,
    is allowed to perform the specified action on the given resource. It uses the Casbin enforcer to make this
    determination based on the loaded policies.

    If the user does not have the required permission, an HTTP 403 Forbidden exception is raised with a detailed
    error message, preventing unauthorized access to protected endpoints.

    Args:
        resource (str): The resource (endpoint) to check access for, e.g., '/health', '/metrics'.
        action (str): The action (e.g., 'GET', 'POST') to check permission for.

    Returns:
        callable: A FastAPI dependency function that performs the permission check.

    Example:
        To protect an endpoint '/health' for GET requests, use:
        `@router.get("/health", dependencies=[Depends(check_permission("/health", "GET"))])`
    """
    async def permission_dependency(
        user_role: str = Depends(get_current_user_role),
        enforcer: casbin.Enforcer = Depends(get_enforcer)
    ):
        if not enforcer.enforce(user_role, resource, action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User with role {user_role} does not have permission to {action} {resource}"
            )
    return permission_dependency 