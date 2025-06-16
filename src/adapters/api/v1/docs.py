"""
API Documentation Endpoints

This module provides custom endpoints for API documentation with access control. These endpoints serve the
Swagger UI and ReDoc interfaces for exploring the API's OpenAPI schema, as well as the raw OpenAPI JSON schema
itself. Access to these documentation endpoints is restricted to users with the 'admin' role to prevent
unauthorized users from viewing detailed API structures, which could expose sensitive implementation details.

The permission checks are enforced using the Casbin access control system, ensuring that only authorized
personnel can access these resources. This is particularly important in production environments where API
documentation should not be publicly accessible.

Endpoints:
    - /docs: Serves the Swagger UI for interactive API documentation.
    - /redoc: Serves the ReDoc interface for a more readable API documentation view.
    - /openapi.json: Provides the raw OpenAPI JSON schema for the API.
"""

from fastapi import APIRouter, Depends, Response
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.openapi.utils import get_openapi
from src.permissions.dependencies import check_permission

router = APIRouter()

@router.get("/docs", dependencies=[Depends(check_permission("/docs", "GET"))])
async def get_documentation():
    """
    Custom endpoint for Swagger UI documentation.

    This endpoint serves the Swagger UI, an interactive interface for exploring and testing the API based on its
    OpenAPI schema. Access is restricted to admin users to protect sensitive API details from unauthorized access.

    Returns:
        HTMLResponse: The Swagger UI HTML page configured to load the OpenAPI schema from /openapi.json.

    Raises:
        HTTPException: If the user does not have the required permissions (HTTP 403 Forbidden), as determined
                       by the Casbin enforcer.
    """
    return get_swagger_ui_html(openapi_url="/openapi.json", title="API Documentation")

@router.get("/redoc", dependencies=[Depends(check_permission("/redoc", "GET"))])
async def get_redoc_documentation():
    """
    Custom endpoint for ReDoc documentation.

    This endpoint serves the ReDoc interface, a clean and readable alternative to Swagger UI for viewing API
    documentation based on the OpenAPI schema. Access is restricted to admin users to ensure that detailed API
    information is only available to authorized personnel.

    Returns:
        HTMLResponse: The ReDoc HTML page configured to load the OpenAPI schema from /openapi.json.

    Raises:
        HTTPException: If the user does not have the required permissions (HTTP 403 Forbidden), as determined
                       by the Casbin enforcer.
    """
    return get_redoc_html(openapi_url="/openapi.json", title="API Documentation")

@router.get("/openapi.json", dependencies=[Depends(check_permission("/openapi.json", "GET"))])
async def get_openapi_json():
    """
    Custom endpoint for OpenAPI JSON schema.

    This endpoint provides the raw OpenAPI JSON schema for the API, which is used by documentation tools like
    Swagger UI and ReDoc to generate interactive documentation. Access is restricted to admin users to prevent
    unauthorized access to detailed API specifications.

    Returns:
        Dict: The OpenAPI schema as a JSON-compatible dictionary, describing all API endpoints, parameters,
              responses, and schemas.

    Raises:
        HTTPException: If the user does not have the required permissions (HTTP 403 Forbidden), as determined
                       by the Casbin enforcer.
    """
    from src.main import app  # Import app to access OpenAPI schema
    return app.openapi() 