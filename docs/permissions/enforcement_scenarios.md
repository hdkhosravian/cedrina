# Enforcement Scenarios in Cedrina Permission System

This document explores various scenarios where permissions are enforced in Cedrina, including common use cases, edge cases, and complex situations. Each scenario illustrates how the Casbin enforcer evaluates access requests based on defined policies.

## 1. Basic Role-Based Access Control (RBAC)

**Scenario**: A user with the 'admin' role attempts to access `/api/v1/admin/policies`.
- **Policy**: `p, admin, /api/v1/admin/*, *`
- **Flow**:
  1. The user is authenticated, and their role is identified as 'admin'.
  2. The Casbin enforcer checks if 'admin' can perform any action (`*`) on `/api/v1/admin/policies`.
  3. Since the policy matches, access is granted.
- **Outcome**: Access allowed (HTTP 200 OK).

**Scenario**: A user with the 'user' role attempts to access `/api/v1/admin/policies`.
- **Policy**: No policy grants 'user' access to `/api/v1/admin/*`.
- **Flow**:
  1. The user's role is identified as 'user'.
  2. The enforcer finds no matching policy allowing access.
  3. Access is denied.
- **Outcome**: Access denied (HTTP 403 Forbidden).

## 2. Attribute-Based Access Control (ABAC)

**Scenario**: Access to `/api/v1/reports` is restricted based on department attribute (e.g., only 'finance' department users).
- **Policy**: `p, dept:finance, /api/v1/reports, read`
- **Flow**:
  1. The user's department attribute is extracted as 'finance'.
  2. The subject is formatted as 'dept:finance'.
  3. The enforcer checks if 'dept:finance' can 'read' `/api/v1/reports`.
  4. Policy matches, so access is granted.
- **Outcome**: Access allowed for finance department users; denied for others.

## 3. Time-Based Access Restrictions

**Scenario**: Access to `/api/v1/emergency` is allowed only during specific hours (e.g., 9 AM to 5 PM).
- **Policy**: Custom matcher in `model.conf` includes time check (requires custom implementation or ABAC with time attribute).
- **Flow**:
  1. The request time is evaluated as an attribute.
  2. If within 9 AM to 5 PM, the policy allows access for authorized roles.
  3. Outside these hours, access is denied regardless of role.
- **Outcome**: Access depends on the time of request.
- **Note**: Cedrina's test suite includes `test_time_based_access_restrictions.py` to validate such scenarios.

## 4. Multi-Role User Access Conflict

**Scenario**: A user has multiple roles ('user' and 'manager'), and policies conflict.
- **Policies**:
  - `p, user, /api/v1/data, read`
  - `p, manager, /api/v1/data, write`
- **Flow**:
  1. The user's roles are identified as both 'user' and 'manager'.
  2. The enforcer evaluates policies for each role.
  3. Since the policy effect is `some(where (p.eft == allow))`, if any role allows the action, access is granted.
  4. For a 'write' action, 'manager' role allows it.
- **Outcome**: Access allowed for 'write' due to 'manager' role.
- **Note**: Tested in `test_multi_role_user_access_conflict.py`.

## 5. Temporary Access Grant

**Scenario**: A contractor is granted temporary access to `/api/v1/temp` for a specific period.
- **Policy**: `p, contractor:temp_2023, /api/v1/temp, read`
- **Flow**:
  1. A temporary role or attribute (`contractor:temp_2023`) is assigned to the user.
  2. Access is granted while the policy is active.
  3. After the period, the policy is removed dynamically via API.
- **Outcome**: Access allowed during the temporary period; denied afterward.
- **Note**: See `test_temporary_access_grant_for_contractor.py` for validation.

## 6. Cross-Department Access with Temporary Roles

**Scenario**: A user from 'engineering' needs temporary access to 'marketing' resources.
- **Policy**: `p, eng:temp_marketing, /api/v1/marketing/*, read`
- **Flow**:
  1. A temporary attribute or role (`eng:temp_marketing`) is added to the user.
  2. Access is granted to marketing resources for the duration of the temporary role.
  3. Policy is removed after the access period.
- **Outcome**: Access allowed temporarily; denied once the policy is revoked.
- **Note**: Tested in `test_cross_department_access_with_temporary_roles.py`.

## 7. Emergency Override Access

**Scenario**: During an emergency, specific users are granted override access to all resources.
- **Policy**: `p, emergency_override, /*, *`
- **Flow**:
  1. An emergency role or attribute is assigned to designated users.
  2. The policy allows access to all endpoints during the emergency.
  3. Policy is removed post-emergency.
- **Outcome**: Full access granted during emergency; normal restrictions apply afterward.
- **Note**: Validated by `test_access_during_emergency_override.py`.

## 8. Dynamic Policy Update During User Session

**Scenario**: A policy is updated while a user is actively making requests.
- **Initial Policy**: `p, user, /api/v1/data, read`
- **Updated Policy**: `p, user, /api/v1/data, write`
- **Flow**:
  1. User initially can only 'read' `/api/v1/data`.
  2. Admin updates policy via API to allow 'write'.
  3. Redis watcher updates the enforcer across instances.
  4. User's next request for 'write' is evaluated against the new policy.
- **Outcome**: Access rights update in real-time without session interruption.
- **Note**: Tested in `test_dynamic_policy_update_during_user_session.py`.

## 9. Rate Limiting During Policy Updates

**Scenario**: Policy management endpoints are rate-limited to prevent abuse during updates.
- **Policy**: Rate limit of 50 requests per minute for POST to `/api/v1/admin/policies`.
- **Flow**:
  1. Admin attempts multiple policy updates rapidly.
  2. After exceeding rate limit, further requests are blocked with HTTP 429 Too Many Requests.
- **Outcome**: Policy updates are throttled to maintain system stability.
- **Note**: See `test_rate_limiting_on_policy_management.py`.

## 10. Edge Case: No Matching Policy

**Scenario**: A user requests access to a resource with no defined policy.
- **Policy**: No policy exists for `/api/v1/undefined`.
- **Flow**:
  1. The enforcer checks for any matching policy.
  2. Finding none, access is denied by default.
- **Outcome**: Access denied (HTTP 403 Forbidden).

## 11. Edge Case: Policy Syntax Error

**Scenario**: A policy in `policy.csv` has incorrect syntax.
- **Policy**: `p, admin, /api/v1/admin/*` (missing action field).
- **Flow**:
  1. During application startup, Casbin attempts to load policies.
  2. Syntax error causes a loading failure or the rule is ignored.
- **Outcome**: Application may fail to start, or the erroneous policy is skipped, potentially denying intended access.
- **Resolution**: Validate policy syntax before deployment or use API for safer policy management.

These scenarios cover the breadth of permission enforcement in Cedrina, from basic access control to complex, dynamic situations. For integration details with API endpoints, refer to the [API Integration Guide](./api_integration.md). 