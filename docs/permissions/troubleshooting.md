# Troubleshooting Cedrina Permission System

This guide addresses common issues encountered with the permission system in Cedrina and provides steps to diagnose and resolve them. It is intended for developers and administrators managing access control.

## 1. General Troubleshooting Approach

When facing issues with permissions, follow these steps:

1. **Review Logs**: Check application logs for Casbin enforcement decisions, policy update events, and error messages. Logs are configured in `logging.ini` and often include details about why access was denied or allowed.
2. **Reproduce the Issue**: Attempt to replicate the problem in a controlled environment (e.g., staging or local development) to understand the conditions under which it occurs.
3. **Check Policies**: Verify the current policies loaded into the enforcer via API (`GET /api/v1/admin/policies`) or by inspecting `policy.csv`.
4. **Validate Configuration**: Ensure `model.conf`, Redis connection, and environment variables are correctly set.
5. **Run Tests**: Use relevant tests from `tests/feature/` or `tests/unit/permissions/` to isolate the issue.

## 2. Common Issues and Solutions

### 2.1 Access Denied (HTTP 403 Forbidden)

**Symptoms**: A user receives a 403 error when attempting to access an endpoint, even though they believe they should have access.

- **Check Subject**: Ensure the subject used in the enforcer check matches the policy. For example, if the policy uses `admin` but the subject is derived as `user:admin`, access will be denied.
  - **Fix**: Review how `get_current_user` formats the subject and adjust policies or code to match.
- **Policy Missing**: Verify that a policy exists for the endpoint and action. Use `GET /api/v1/admin/policies` to list current policies.
  - **Fix**: Add the necessary policy via API or by updating `policy.csv` and restarting.
- **Incorrect Path**: Ensure the endpoint path in the policy matches the requested path (e.g., `/api/v1/admin/*` vs. `/api/v1/admin/policies/`).
  - **Fix**: Correct the policy to cover the exact path or use wildcards appropriately.
- **Action Mismatch**: Check if the action in the policy matches the HTTP method (e.g., `read` for GET).
  - **Fix**: Update the policy to include the correct action or use `*` for all actions.

**Test**: Run `test_user_access.py` to simulate access denial scenarios.

### 2.2 Unauthorized Access Allowed

**Symptoms**: A user without proper permissions can access a restricted endpoint.

- **Policy Overlap**: Check for overly broad policies (e.g., `p, user, /*, *`) that might grant unintended access.
  - **Fix**: Narrow down policies to specific paths and actions.
- **Subject Misidentification**: Verify that `get_current_user` returns the correct user role or attributes.
  - **Fix**: Debug the authentication dependency to ensure accurate user data.
- **Policy Effect**: Ensure the `model.conf` policy effect isn't set to allow access by default (e.g., `some(where (p.eft == allow))`).
  - **Fix**: Adjust the policy effect if deny-by-default is desired, though this requires careful policy redesign.

**Test**: Use `test_admin_access.py` to ensure only authorized users access admin endpoints.

### 2.3 Policy Updates Not Reflecting

**Symptoms**: Policies updated via API or `policy.csv` do not affect access decisions.

- **Redis Sync Issue**: If using Redis for dynamic updates, ensure the Redis watcher is active and connected (`src/permissions/redis_watcher.py`).
  - **Fix**: Check `REDIS_URL` environment variable and Redis server status. Restart the application if necessary.
- **Cache**: The enforcer might be using cached policies.
  - **Fix**: Restart the application to force a policy reload, or ensure the Redis adapter is correctly updating.
- **API Update Failure**: Check audit logs for errors during policy update requests.
  - **Fix**: Retry the update and ensure the API request payload is correct.

**Test**: Run `test_dynamic_policy_update_during_user_session.py` to validate real-time policy updates.

### 2.4 Application Fails to Start Due to Permission Config

**Symptoms**: Application startup fails with errors related to Casbin or policy loading.

- **Syntax Error in model.conf**: Validate the syntax of `model.conf` for typos or incorrect sections.
  - **Fix**: Use Casbin's syntax checker or compare with a known good configuration.
- **Policy File Not Found**: Ensure `policy.csv` exists at the path specified by `POLICY_FILE_PATH`.
  - **Fix**: Correct the path or create the file if missing.
- **Redis Connection Failure**: If using Redis, check connection errors in logs.
  - **Fix**: Verify `REDIS_URL` and ensure Redis server is running.

### 2.5 Rate Limiting Blocks Policy Management

**Symptoms**: Attempts to update policies via API return HTTP 429 Too Many Requests.

- **Rate Limit Exceeded**: Cedrina rate-limits policy management endpoints (e.g., 50/minute for POST).
  - **Fix**: Wait for the rate limit window to reset, or batch updates using bulk API endpoints (`POST /api/v1/admin/policies/bulk`).
- **Configuration**: Check if rate limits are too restrictive for your use case.
  - **Fix**: Adjust rate limits in `src/adapters/api/v1/admin/policies.py` if necessary (e.g., increase to 100/minute).

**Test**: Run `test_rate_limiting_on_policy_management.py` to simulate rate limit enforcement.

### 2.6 Audit Logs Not Capturing Policy Changes

**Symptoms**: Policy changes are made, but audit logs do not reflect them.

- **Logging Configuration**: Ensure logging is enabled for policy management endpoints.
  - **Fix**: Check `logging.ini` and ensure handlers for audit logs are active.
- **Database Issue**: Verify the database connection for storing logs.
  - **Fix**: Debug database connectivity and ensure the audit log table exists.

**Test**: Run `test_audit_logging_for_policy_changes.py` to validate logging behavior.

### 2.7 Test Failures Related to Permissions

**Symptoms**: Tests in `tests/feature/` or `tests/unit/permissions/` fail unexpectedly.

- **Isolation Issues**: Tests might interfere with each other due to shared state (e.g., database or policy state).
  - **Fix**: Ensure fixtures like `database_cleanup` in `conftest.py` reset state between tests.
- **Mocking Errors**: Incorrect mock setup for `get_current_user` or `get_enforcer`.
  - **Fix**: Review mock logic to ensure it simulates the intended user or policy behavior.
- **Policy Mismatch**: Test might expect a specific policy that isn't loaded.
  - **Fix**: Explicitly set up test-specific policies or mock the enforcer to return expected results.

**Action**: Run failing tests individually (`pytest -k test_name -v`) to isolate the issue.

## 3. Debugging Techniques

- **Enable Detailed Logging**: Temporarily increase log verbosity for Casbin decisions by adjusting `logging.ini` to include debug-level logs for `casbin` and related modules.
- **Trace Enforcer Decisions**: Add print statements or log entries in `enforcer.py` to see the subject, object, and action being evaluated.
- **API Debugging**: Use tools like Postman to manually test API endpoints with different user tokens and observe permission responses.
- **Policy Dump**: Export current policies from the enforcer or database to a file for inspection during debugging.

## 4. Preventive Measures

- **Policy Validation**: Before applying policies, validate their syntax and logic in a non-production environment.
- **Regular Backups**: Backup `policy.csv` and database policy tables to recover from accidental policy loss or corruption.
- **Monitoring**: Set up monitoring alerts for unusual access patterns (e.g., frequent 403s or 429s) to catch issues early.
- **Documentation**: Maintain clear documentation of policies and their intended effects to aid troubleshooting.

## 5. When to Escalate

If issues persist after following this guide:
- **Check Casbin Documentation**: Refer to the official Casbin documentation for advanced configuration or matcher issues.
- **Community Support**: Raise questions in the Casbin GitHub issues or forums with detailed logs and reproduction steps.
- **Internal Review**: If in a team environment, escalate to senior developers or security specialists for complex policy or integration problems.

This troubleshooting guide should help resolve most permission-related issues in Cedrina. For a deeper understanding of specific components, refer to the other guides in this directory, starting with the [Core Concepts](./core_concepts.md). 