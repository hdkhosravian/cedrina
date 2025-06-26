# Policy Management in Cedrina Permission System

This guide covers the management of access control policies in Cedrina, including creating, updating, and deleting policies both statically and dynamically using the **6-parameter ABAC model**.

## 1. Understanding Policy Structure

Policies in Cedrina use a **6-parameter Attribute-Based Access Control (ABAC)** model that defines who (subject) can do what (action) on which resources (object) with additional contextual attributes. The structure of a policy rule is:

- **Subject**: The entity (user, role) requesting access
- **Object**: The resource or endpoint being accessed (e.g., `/admin/policies`)
- **Action**: The operation (e.g., `GET`, `POST`)
- **Department**: User's department attribute (use `*` for any)
- **Location**: User's location attribute (use `*` for any)
- **Time of Day**: Time-based access attribute (use `*` for any)

A policy rule in `policy.csv` looks like:

```
p, admin, /admin/policies, POST, *, *, *
```

This rule allows any user with the 'admin' role to perform POST actions on `/admin/policies` regardless of department, location, or time constraints.

## 2. Static Policy Management

Static policies are defined in the `policy.csv` file located at `src/permissions/policy.csv`. To manage policies statically:

1. **Edit the CSV File**: Open the file in a text editor
2. **Add a Rule**: Append a new line with the 6-parameter policy rule format
3. **Modify a Rule**: Find the existing rule and update the parameters as necessary
4. **Delete a Rule**: Remove the line corresponding to the rule you wish to delete
5. **Apply Changes**: Restart the application to load the updated policies into the Casbin enforcer

**Example Policy Rules**:
```
# Admin access to health endpoints
p, admin, /health, GET, *, *, *
# User access to profile with department restriction
p, user, /profile, GET, finance, *, *
# Time-based access to reports
p, manager, /reports, GET, *, *, business_hours
```

**Note**: Static changes require an application restart, which might not be ideal for production environments.

## 3. Dynamic Policy Management

Cedrina supports dynamic policy updates through API endpoints, allowing changes without restarting the application. This is managed via the admin API at `/api/v1/admin/policies`.

### 3.1 Adding a Policy

- **Endpoint**: `POST /api/v1/admin/policies/add`
- **Rate Limit**: 50 requests per minute
- **Payload Example**:
  ```json
  {
    "subject": "manager",
    "object": "/reports",
    "action": "GET",
    "sub_dept": "finance",
    "sub_loc": "*",
    "time_of_day": "*"
  }
  ```
- **Response**: Returns a success message if the policy is added
- **Behavior**: The new policy is immediately enforced across all instances due to the Redis watcher

### 3.2 Removing a Policy

- **Endpoint**: `POST /api/v1/admin/policies/remove`
- **Rate Limit**: 50 requests per minute
- **Payload Example**:
  ```json
  {
    "subject": "manager",
    "object": "/reports",
    "action": "GET",
    "sub_dept": "finance",
    "sub_loc": "*",
    "time_of_day": "*"
  }
  ```
- **Response**: Confirms deletion of the policy
- **Behavior**: The policy is removed from enforcement immediately

### 3.3 Listing Policies

- **Endpoint**: `GET /api/v1/admin/policies`
- **Rate Limit**: 100 requests per minute
- **Response Example**:
  ```json
  {
    "policies": [
      {
        "subject": "admin",
        "object": "/health",
        "action": "GET",
        "attributes": {
          "sub_dept": "*",
          "sub_loc": "*", 
          "time_of_day": "*"
        }
      }
    ],
    "count": 1
  }
  ```

## 4. ABAC Attribute Usage

The 6-parameter model supports sophisticated access control scenarios:

### 4.1 Department-Based Access
```
p, user, /finance-reports, GET, finance, *, *
```
Only users in the finance department can access finance reports.

### 4.2 Location-Based Access
```
p, admin, /local-admin, POST, *, headquarters, *
```
Admin actions restricted to headquarters location only.

### 4.3 Time-Based Access
```
p, contractor, /temp-access, GET, *, *, business_hours
```
Contractor access limited to business hours.

### 4.4 Combined Attributes
```
p, manager, /sensitive-data, GET, finance, headquarters, business_hours
```
Access requires all three conditions: finance department, headquarters location, and business hours.

## 5. Audit Logging for Policy Changes

Every policy change through the API is comprehensively logged with:
- **Who**: User ID and username of the person making the change
- **What**: Specific policy added/removed with all parameters
- **When**: Timestamp of the change
- **Where**: IP address and user agent
- **Context**: Request locale and additional metadata

These logs are stored in the database and can be accessed for compliance and troubleshooting. The audit system is tested in `test_audit_logging_for_policy_changes.py`.

## 6. Policy Versioning and Rollback

Cedrina supports policy change tracking through audit logs:
- **Retrieve Policy History**: Query audit logs to view all policy changes over time
- **Rollback**: Use the audit logs to identify previous policy states and manually reapply them via API
- **Change Analysis**: Analyze policy changes to understand access pattern evolution

## 7. Best Practices for Policy Management

- **Use Wildcards Appropriately**: Use `*` for attributes that don't apply to specific policies
- **Granular ABAC Policies**: Define policies at the most granular level using department, location, and time attributes
- **Regular Policy Reviews**: Periodically review policies to ensure they align with current organizational structure
- **Test Before Deployment**: Use the comprehensive test suite to simulate policy changes
- **Document Complex Policies**: Document the rationale behind complex ABAC rules for future administrators
- **Monitor Performance**: ABAC evaluation is more complex than RBAC; monitor performance impact

## 8. Handling Policy Conflicts

With the 6-parameter model, conflicts can occur when multiple rules apply. Casbin resolves conflicts based on the policy effect in `model.conf`:
- **Allow-by-Default**: If any policy allows access (`some(where (p.eft == allow))`), access is granted
- **Attribute Matching**: All specified attributes must match; wildcards (*) match any value
- **Explicit Policies**: Make policies as explicit as possible to reduce ambiguity

## 9. Integration with User Attributes

The permission system extracts user attributes for ABAC evaluation:
- **Department**: Retrieved from user profile or defaults to `*`
- **Location**: Retrieved from user context or defaults to `*`
- **Time of Day**: Can be dynamically calculated or set based on business rules

For more on how policies are enforced in various scenarios, refer to the [Enforcement Scenarios Guide](./enforcement_scenarios.md). 