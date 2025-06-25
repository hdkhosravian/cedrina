# Configuration of Cedrina Permission System

This guide provides detailed instructions on how to configure the permission system in Cedrina, which uses Casbin for access control.

## 1. Casbin Enforcer Setup

The Casbin enforcer is initialized in `src/permissions/enforcer.py`. Here's how it's configured:

- **Model Configuration**: The enforcer uses a model configuration file (`model.conf`) that defines the structure of the access control model. This file specifies the request definition, policy definition, role definition, policy effect, and matchers for **Attribute-Based Access Control (ABAC)**.
  
  ```
  [request_definition]
  r = sub, obj, act, sub_dept, sub_loc, time_of_day

  [policy_definition]
  p = sub, obj, act, sub_dept, sub_loc, time_of_day

  [role_definition]
  g = _, _

  [policy_effect]
  e = some(where (p.eft == allow))

  [matchers]
  m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act && (r.sub_dept == p.sub_dept || p.sub_dept == "*") && (r.sub_loc == p.sub_loc || p.sub_loc == "*") && (r.time_of_day == p.time_of_day || p.time_of_day == "*")
  ```

  **Note**: This configuration supports ABAC with department, location, and time-based attributes. The wildcard "*" allows flexible matching when specific attributes are not required.

- **Adapter**: Cedrina uses a **SQLAlchemy adapter** as the primary storage mechanism for policies, with automatic fallback to a file adapter if database connection fails. This ensures policy persistence and consistency across restarts.

- **Redis Watcher**: A Redis watcher is set up to monitor policy changes and update the enforcer in real-time across multiple instances. This is configured in `src/permissions/redis_watcher.py` using Redis pub/sub with database 1 to avoid conflicts.

## 2. Policy File Configuration

Policies are initially defined in `src/permissions/policy.csv`. This file contains rules in the **6-parameter ABAC format**:

```
p, admin, /health, GET, *, *, *
p, admin, /metrics, GET, *, *, *
p, admin, /admin/policies, POST, *, *, *
p, user, /profile, GET, *, *, *
```

- Each line represents a policy rule with 6 parameters:
  1. `p` - Indicates it's a policy rule
  2. **Subject** - Role or user (e.g., admin, user)
  3. **Object** - Resource path (e.g., /health, /admin/policies)
  4. **Action** - HTTP method (e.g., GET, POST)
  5. **Department** - User department attribute (use "*" for any)
  6. **Location** - User location attribute (use "*" for any)  
  7. **Time of Day** - Time-based access attribute (use "*" for any)

## 3. Environment Variables

Several environment variables can be set to customize the permission system behavior:

- `REDIS_HOST`: Redis server hostname (default: localhost)
- `REDIS_PORT`: Redis server port (default: 6379)
- `REDIS_PASSWORD`: Redis authentication password (optional)
- `REDIS_URL`: Complete Redis connection URL (alternative to individual settings)

These variables are loaded in `src/core/config/settings.py` and used by both the enforcer and Redis watcher.

## 4. Customizing Policies

To customize policies, you can:

- **Edit the CSV File**: Directly modify `policy.csv` for static changes. Remember to use the 6-parameter format with wildcards (*) for unused attributes.
- **Use Admin API Endpoints**: Dynamically update policies at runtime using the admin API endpoints:
  - `POST /api/v1/admin/policies/add` - Add new policies
  - `POST /api/v1/admin/policies/remove` - Remove policies
  - `GET /api/v1/admin/policies` - List current policies

## 5. Integration with Application Settings

The permission system configuration is tied to the application settings in `src/core/config/settings.py`. Key integration points:

- **Database Connection**: The SQLAlchemy adapter uses the main application database engine
- **Redis Configuration**: Redis settings are shared between the watcher and other application components
- **Logging**: Policy operations are logged using the application's logging configuration

## 6. Validation and Testing

After making configuration changes:
- **Validate Syntax**: Ensure that the `model.conf` syntax is correct, especially the ABAC matcher logic
- **Test Policies**: Use the comprehensive test suite in `tests/feature/` and `tests/unit/permissions/` to validate policy behavior
- **Verify ABAC Attributes**: Test that department, location, and time-based restrictions work as expected

## 7. Best Practices

- **ABAC Usage**: Use wildcards (*) for attributes that don't apply to specific policies to maintain flexibility
- **Database Persistence**: Rely on the SQLAlchemy adapter for production to ensure policy persistence
- **Redis Synchronization**: Ensure Redis is properly configured for multi-instance deployments
- **Regular Backups**: Backup both the database policy tables and the fallback `policy.csv` file
- **Audit Logging**: All policy changes through the API are automatically logged with detailed metadata

For more information on managing policies dynamically, refer to the [Policy Management Guide](./policy_management.md). 