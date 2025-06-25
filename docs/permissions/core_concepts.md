# Core Concepts of Cedrina Permission System

This document outlines the fundamental concepts behind the permission system used in Cedrina, which is built on top of Casbin with a **6-parameter Attribute-Based Access Control (ABAC)** model.

## 1. Access Control Models

Cedrina's permission system is primarily built around **Attribute-Based Access Control (ABAC)** with support for role-based elements:

- **Attribute-Based Access Control (ABAC)**: The primary model using 6 parameters: subject (role), object (resource), action, department, location, and time-of-day. This allows for sophisticated access control based on multiple contextual attributes.
- **Role-Based Access Control (RBAC)**: Implemented as part of the ABAC model where the subject parameter represents user roles (admin, user, etc.).
- **Hybrid Approach**: Combines the simplicity of RBAC with the flexibility of ABAC for complex scenarios.

## 2. Key Components

The Cedrina permission system uses a **6-parameter model** for comprehensive access control:

- **Subject**: The entity requesting access, typically a user role (e.g., 'admin', 'user', 'manager')
- **Object**: The resource being accessed, such as an API endpoint (e.g., `/admin/policies`, `/health`)
- **Action**: The operation being performed (e.g., 'GET', 'POST', 'PUT', 'DELETE')
- **Department**: User's department attribute for organizational access control (e.g., 'finance', 'engineering', or '*' for any)
- **Location**: User's location attribute for geographical access control (e.g., 'headquarters', 'remote', or '*' for any)
- **Time of Day**: Temporal access control attribute (e.g., 'business_hours', 'after_hours', or '*' for any time)

- **Policy**: A rule defining whether a subject can perform an action on an object with specific attribute constraints
- **Enforcer**: The Casbin component that evaluates access requests against the defined policies using the 6-parameter model

## 3. Policy Definition

Policies in Cedrina are defined using the 6-parameter ABAC syntax in the `policy.csv` file or dynamically through API endpoints. Policy rules follow this format:

```
p, <subject>, <object>, <action>, <department>, <location>, <time_of_day>
```

**Examples**:
```
# Admin access to health endpoints (no attribute restrictions)
p, admin, /health, GET, *, *, *

# Finance department access to reports during business hours
p, user, /reports, GET, finance, *, business_hours

# Manager access to admin functions from headquarters only
p, manager, /admin/policies, POST, *, headquarters, *

# Contractor access to temporary resources with multiple restrictions
p, contractor, /temp-access, GET, engineering, remote, business_hours
```

The wildcard `*` is used for attributes that don't apply to a specific policy, providing flexibility in policy definition.

## 4. Enforcement Flow

1. **Request Initiation**: A user makes a request to access a resource (e.g., an API endpoint)
2. **Authentication**: The system authenticates the user through the `get_current_user` dependency
3. **Attribute Extraction**: User attributes are extracted:
   - Role from `user.role.value`
   - Department from `user.department` (defaults to '*')
   - Location from `user.location` (defaults to '*')
   - Time context from `user.time_of_day` or calculated dynamically (defaults to '*')
4. **Policy Evaluation**: The Casbin enforcer evaluates the request using all 6 parameters:
   ```python
   result = enforcer.enforce(role, resource, action, department, location, time_of_day)
   ```
5. **Matcher Logic**: The model's matcher evaluates:
   - Role and resource must match exactly
   - Action must match exactly
   - Attributes match if they're identical OR if the policy uses wildcard '*'
6. **Decision**: If any policy allows access, the request proceeds. If denied, an HTTP 403 Forbidden exception is raised

## 5. Integration with FastAPI

The permission system integrates with FastAPI through several mechanisms:

- **check_permission Dependency**: Factory function that creates FastAPI dependencies for specific resource/action combinations
- **Automatic ABAC Evaluation**: Dependencies automatically extract user attributes and perform 6-parameter enforcement
- **Custom Enforcement**: Endpoints can perform manual enforcement with custom attribute logic

Example integration:
```python
@router.get("/reports", dependencies=[Depends(check_permission("/reports", "GET"))])
async def get_reports():
    # Automatically enforces ABAC policy with user's attributes
    return {"reports": [...]}
```

## 6. Dynamic Policy Updates

Cedrina supports real-time policy updates through:

- **Admin API Endpoints**: RESTful endpoints for adding, removing, and listing policies
- **Database Persistence**: Policies are stored in the database using SQLAlchemy adapter
- **Redis Synchronization**: Redis watcher ensures policy changes propagate across multiple instances
- **Immediate Effect**: Policy changes take effect immediately without application restart

## 7. ABAC Attribute Flexibility

The 6-parameter model provides flexibility through:

- **Wildcard Support**: Use '*' for attributes that don't apply to specific policies
- **Dynamic Attributes**: Attributes can be calculated at runtime (e.g., time-based access)
- **Hierarchical Policies**: Combine broad and specific policies for layered access control
- **Context-Aware Access**: Access decisions based on user context, location, and time

## 8. Policy Evaluation Logic

The Casbin matcher implements the following logic:
```
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act && 
    (r.sub_dept == p.sub_dept || p.sub_dept == "*") && 
    (r.sub_loc == p.sub_loc || p.sub_loc == "*") && 
    (r.time_of_day == p.time_of_day || p.time_of_day == "*")
```

This ensures:
- Exact matching for role, resource, and action
- Flexible matching for attributes (exact match OR wildcard)
- Allow-by-default policy effect (`some(where (p.eft == allow))`)

## 9. Performance Considerations

The 6-parameter ABAC model has performance implications:

- **More Complex Evaluation**: Each request evaluates 6 parameters instead of 3
- **Attribute Extraction Overhead**: Additional processing to extract user attributes
- **Policy Set Size**: More granular policies may result in larger policy sets
- **Caching**: Enforcer caching helps mitigate performance impact
- **Monitoring**: Performance monitoring is recommended for high-traffic deployments

Understanding these core concepts is crucial for effectively managing access control in Cedrina. The 6-parameter ABAC model provides powerful flexibility while maintaining the simplicity of role-based access where attributes aren't needed. For more detailed information on configuring the system, refer to the [Configuration Guide](./configuration.md). 