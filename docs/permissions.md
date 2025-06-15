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

Run the tests with:

```bash
poetry run pytest tests/unit/permissions/
```

## Integration with Authentication

The permission system relies on user role information from the authentication system. Currently, `get_current_user_role()` in `dependencies.py` is a placeholder. To fully integrate:

1. Update `get_current_user_role()` to extract the role from the authenticated user's token or session.
2. Ensure the role matches the ones defined in `policy.csv` (e.g., `admin`).

Example placeholder in `dependencies.py`:

```python
async def get_current_user_role() -> str:
    # TODO: Integrate with auth system to get the actual user role
    return "admin"  # Placeholder for testing
```

## Troubleshooting

- **403 Forbidden Errors**: Check if the user's role matches a policy in `policy.csv` for the requested resource and action. Ensure `get_current_user_role()` returns the correct role.
- **Policy Not Applied**: Verify that `model.conf` and `policy.csv` are correctly loaded by the enforcer. Check logs for initialization errors.
- **Testing Failures**: Ensure mocks in tests simulate the expected behavior of the enforcer and user roles.

## Future Enhancements

- **Database Storage**: Currently, policies are file-based (`policy.csv`). For scalability, consider migrating to a database adapter for Casbin.
- **Dynamic Roles**: Implement support for dynamic role assignment based on user attributes or groups.
- **Audit Logging**: Add logging for permission checks to track access attempts for security auditing.

This permission system provides a robust foundation for access control, ensuring that sensitive endpoints are protected while maintaining flexibility for future extensions. 