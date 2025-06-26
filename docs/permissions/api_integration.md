# API Integration of Cedrina Permission System

This guide details how the permission system in Cedrina integrates with FastAPI endpoints to enforce access control using the **6-parameter ABAC model**. Understanding this integration is crucial for developers adding new endpoints or modifying existing ones.

## 1. Dependency Injection for Permissions

Cedrina uses FastAPI's dependency injection system to enforce permissions. The key dependencies are:

- **get_current_user**: Defined in `src/core/dependencies/auth.py`, this dependency authenticates the user making the request and returns a `User` object with details like username, role, and ABAC attributes.
- **get_enforcer**: Defined in `src/permissions/enforcer.py`, this dependency provides the Casbin enforcer instance used to evaluate access policies.
- **check_permission**: Defined in `src/permissions/dependencies.py`, this is a factory function that creates FastAPI dependencies for specific resource and action combinations.

These dependencies are injected into route definitions to ensure that permission checks are performed before the endpoint logic is executed.

## 2. Protecting Endpoints with Permission Dependencies

The primary method for protecting endpoints is using the `check_permission` dependency factory. Here's an example from `src/adapters/api/v1/admin/policies.py`:

```python
from fastapi import APIRouter, Depends
from src.permissions.dependencies import check_permission

router = APIRouter()

@router.get("/policies", dependencies=[Depends(check_permission("/admin/policies", "GET"))])
async def get_policies():
    # Endpoint logic here
    return {'message': 'Policies retrieved'}

@router.post("/policies/add", dependencies=[Depends(check_permission("/admin/policies", "POST"))])
async def add_policy():
    # Endpoint logic here
    return {'message': 'Policy added'}
```

- **check_permission**: Creates a dependency that enforces permission for the specified resource and action
- **Automatic ABAC Evaluation**: The dependency automatically extracts user attributes and evaluates them against the 6-parameter model

## 3. Custom Permission Checks with ABAC

For more granular control, you can implement custom permission checks within the endpoint using the 6-parameter ABAC model:

```python
from fastapi import Depends, HTTPException
from src.core.dependencies.auth import get_current_user
from src.permissions.enforcer import get_enforcer
from src.domain.entities.user import User
import casbin

@router.post('/sensitive-data')
async def access_sensitive_data(
    user: User = Depends(get_current_user),
    enforcer: casbin.Enforcer = Depends(get_enforcer)
):
    # Extract user attributes for ABAC
    user_role = user.role.value
    user_dept = getattr(user, 'department', '*')
    user_location = getattr(user, 'location', '*')
    time_of_day = getattr(user, 'time_of_day', '*')
    
    # Perform 6-parameter enforcement
    if not enforcer.enforce(user_role, '/sensitive-data', 'POST', user_dept, user_location, time_of_day):
        raise HTTPException(status_code=403, detail='Permission denied')
    
    # Proceed with business logic
    return {'message': 'Access granted to sensitive data'}
```

## 4. ABAC Attribute Extraction

The permission system extracts user attributes for ABAC evaluation from multiple sources:

- **Role**: Always extracted from `user.role.value`
- **Department**: Retrieved from `user.department` or defaults to `*`
- **Location**: Retrieved from `user.location` or defaults to `*`
- **Time of Day**: Can be dynamically calculated or retrieved from user context, defaults to `*`

The `check_permission` dependency automatically handles this extraction in `src/permissions/dependencies.py`:

```python
async def permission_dependency(
    request: Request,
    current_user: User = Depends(get_current_user),
    enforcer: casbin.Enforcer = Depends(get_enforcer)
):
    user_role = current_user.role.value
    sub_dept = getattr(current_user, 'department', '*')
    sub_loc = getattr(current_user, 'location', '*')
    time_of_day = getattr(current_user, 'time_of_day', '*')
    
    result = enforcer.enforce(user_role, resource, action, sub_dept, sub_loc, time_of_day)
    if not result:
        raise PermissionError("Access denied")
```

## 5. Object and Action Mapping

- **Object**: The resource being accessed is mapped to the endpoint path. In the current implementation, paths are simplified (e.g., `/admin/policies` instead of `/api/v1/admin/policies`)
- **Action**: The action corresponds directly to HTTP methods:
  - GET -> 'GET'
  - POST -> 'POST'
  - PUT -> 'PUT'
  - DELETE -> 'DELETE'

## 6. Rate Limiting Integration

Permission management endpoints are rate-limited to prevent abuse:

- **GET /api/v1/admin/policies**: 100 requests per minute
- **POST /api/v1/admin/policies/add**: 50 requests per minute
- **POST /api/v1/admin/policies/remove**: 50 requests per minute

Rate limiting is implemented using `slowapi` and configured in `src/adapters/api/v1/admin/policies.py`:

```python
from slowapi import Limiter

limiter = Limiter(key_func=get_remote_address)

@router.post("/policies/add")
@limiter.limit("50/minute")
async def add_policy():
    # Implementation
```

## 7. Error Handling and Internationalization

When permission is denied:
- **Standard Response**: A `PermissionError` is raised, which is handled by the application's exception handlers
- **HTTP Status**: Returns HTTP 403 Forbidden
- **Internationalized Messages**: Error messages are translated based on the user's locale using `get_translated_message()`
- **Detailed Logging**: Permission denials are logged with user role, resource, and action details

Example error handling in `src/permissions/dependencies.py`:

```python
if not result:
    message = get_translated_message("permission_denied_for_action", locale).format(
        role=user_role, action=action, resource=resource
    )
    logger.warning(f"Permission denied: Role {user_role} cannot {action} on {resource}")
    raise PermissionError(message)
```

## 8. Testing API Integration

Cedrina includes comprehensive tests for API integration:

- **Unit Tests**: Located in `tests/unit/permissions/` to test individual components
- **Feature Tests**: Located in `tests/feature/` to test end-to-end scenarios with real API calls
- **ABAC Testing**: Specific tests for department, location, and time-based access restrictions

Example test structure:
```python
@pytest.mark.asyncio
async def test_department_based_access(client, finance_user_token):
    headers = {'Authorization': f'Bearer {finance_user_token}'}
    response = await client.get('/api/v1/finance-reports', headers=headers)
    assert response.status_code == 200
```

## 9. Best Practices for Developers

- **Use check_permission Dependency**: Prefer the `check_permission` dependency over manual enforcement for consistency
- **Consistent Resource Naming**: Use consistent resource path naming across policies and endpoints
- **ABAC Attribute Handling**: Ensure user objects have appropriate ABAC attributes set or use sensible defaults
- **Test All Scenarios**: Write tests for different combinations of ABAC attributes
- **Performance Considerations**: ABAC evaluation is more complex than RBAC; monitor performance impact
- **Logging**: Ensure adequate logging for permission decisions to aid debugging

## 10. Extending Permissions for New Endpoints

When adding a new endpoint with ABAC support:

1. **Define Policy**: Add a policy in `policy.csv` or via API with appropriate ABAC attributes:
   ```
   p, manager, /new-endpoint, GET, finance, *, business_hours
   ```

2. **Add Dependency**: Include the `check_permission` dependency in the route definition:
   ```python
   @router.get("/new-endpoint", dependencies=[Depends(check_permission("/new-endpoint", "GET"))])
   ```

3. **Set User Attributes**: Ensure the user object has the necessary ABAC attributes populated

4. **Test**: Write comprehensive tests covering different attribute combinations

## 11. Advanced ABAC Scenarios

For complex ABAC scenarios, you can implement custom logic:

```python
@router.get("/dynamic-access")
async def dynamic_access(
    user: User = Depends(get_current_user),
    enforcer: casbin.Enforcer = Depends(get_enforcer)
):
    # Dynamic time calculation
    current_hour = datetime.now().hour
    time_context = "business_hours" if 9 <= current_hour <= 17 else "after_hours"
    
    # Dynamic department from request context
    department = request.headers.get('X-Department', getattr(user, 'department', '*'))
    
    if not enforcer.enforce(user.role.value, '/dynamic-access', 'GET', department, user.location, time_context):
        raise HTTPException(status_code=403, detail='Access denied for current context')
    
    return {'message': 'Access granted with dynamic attributes'}
```

For troubleshooting issues related to permission integration, refer to the [Troubleshooting Guide](./troubleshooting.md). 