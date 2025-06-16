# Permission System Documentation

## Overview

The permission system in this project is built using **Casbin**, an open-source access control library that supports various access control models like Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC). This system is designed to restrict access to specific API endpoints based on user roles, ensuring that sensitive operations are only accessible to authorized personnel.

The primary goal of this implementation is to secure endpoints such as `/health`, `/docs`, `/redoc`, and `/metrics` by allowing access only to users with the `admin` role. The system is modular, scalable, and adheres to clean code practices and SOLID principles.

## Architecture

The permission system is organized into a dedicated module under `src/permissions/` with the following components:

- **config.py**: Defines configuration settings for the Casbin enforcer, such as paths to the model and policy files.
- **enforcer.py**: Initializes and manages the Casbin enforcer instance, which evaluates access control policies.
- **dependencies.py**: Provides FastAPI dependency functions to check permissions for specific resources and actions.
- **policies.py**: Manages policy definitions, allowing for dynamic updates to access rules.
- **model.conf**: The Casbin model configuration file defining the access control model (currently RBAC with resources and actions).
- **policy.csv**: A file-based storage for policy rules, mapping roles to resources and actions (e.g., `admin` can `GET` `/health`).

This modular structure separates concerns, making it easier to maintain and extend the permission system.

## Setup

### Dependencies

The permission system relies on the `casbin` library, which is included in the project's dependencies via Poetry. To ensure it's installed:

```bash
poetry install
```

### Configuration

The Casbin model and policy files are located in `src/permissions/`:
- **Model**: `model.conf` defines the RBAC model with support for resources and actions.
- **Policy**: `policy.csv` contains rules like `p, admin, /health, GET` to allow admin access to the health endpoint.

These files are loaded by `config.py` and used to initialize the enforcer in `enforcer.py`.

## Usage

### Protecting Endpoints

To protect an endpoint, use the `check_permission` dependency from `src/permissions/dependencies.py`. Specify the resource (endpoint path) and action (HTTP method) to enforce access control.

Example from `src/adapters/api/v1/health.py`:

```python
from fastapi import APIRouter, Depends
from src.permissions.dependencies import check_permission

router = APIRouter()

@router.get("/health", dependencies=[Depends(check_permission("/health", "GET"))])
async def get_health():
    return {"status": "ok"}
```

In this example, only users with a role that has permission to `GET` `/health` (currently only `admin`) can access the endpoint. Unauthorized access results in a `403 Forbidden` response.

### Custom Protected Endpoints for Docs and Redoc

To secure Swagger UI and Redoc documentation:
- Default documentation endpoints are disabled in `src/main.py`.
- Custom endpoints `/docs` and `/redoc` are defined in `src/adapters/api/v1/docs.py` with permission checks.
- Only `admin` users can access these documentation endpoints.

### Extending Policies

To add new policies or modify existing ones, update `policy.csv` or use the functions in `policies.py` to manage rules programmatically. For example, to allow a new role `manager` to access `/metrics`:

```python
from src.permissions.policies import add_policy

add_policy("manager", "/metrics", "GET")
```

## Testing

A comprehensive test suite for the permission system is located in `tests/unit/permissions/`. It includes:

- **Unit Tests**: Covering configuration, enforcer initialization, policy management, and dependency logic.
- **Integration Tests**: Simulating API requests to protected endpoints with different user roles to verify access control.
- **Edge Cases**: Testing token expiration, role changes, concurrent access, and malformed tokens.

Run the tests with:

```bash
poetry run pytest tests/unit/permissions/
```

## Integration with Authentication

The permission system is now fully integrated with the application's JWT-based authentication system. Access control is enforced by a series of dependencies that work together:

1. **`oauth2_scheme`**: A standard FastAPI `OAuth2PasswordBearer` dependency that extracts the bearer token from the `Authorization` header.

2. **`get_current_user`**: A dependency located in `src/core/dependencies/auth.py`. It receives the token, validates it using the `TokenService`, and fetches the corresponding `User` from the database. It raises a 401 Unauthorized error if the token is invalid, expired, or the user is not active.

3. **`check_permission`**: The Casbin permission dependency in `src/permissions/dependencies.py`. It now depends on `get_current_user` to get the authenticated user. It then uses the user's role (`current_user.role`) to enforce the policy. If the user's role is not sufficient, it raises a 403 Forbidden error.

This setup ensures that only actively authenticated users with the correct role can access protected endpoints.

## Troubleshooting

- **401 Unauthorized Errors**: This indicates a problem with the JWT token. Ensure a valid, non-expired token is being sent in the `Authorization: Bearer <token>` header.
- **403 Forbidden Errors**: This means the authenticated user does not have the required role for the resource. Check the policies in `src/permissions/policy.csv` and the user's role in the database.

## Future Enhancements

- **Database Storage**: Currently, policies are file-based (`policy.csv`). For scalability, consider migrating to a database adapter for Casbin.
- **Dynamic Roles**: Implement support for dynamic role assignment based on user attributes or groups.
- **Audit Logging**: Add logging for permission checks to track access attempts for security auditing.

This permission system provides a robust foundation for access control, ensuring that sensitive endpoints are protected while maintaining flexibility for future extensions. 