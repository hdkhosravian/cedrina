# Testing and Validation of Cedrina Permission System

This guide covers best practices for testing and validating the permission system in Cedrina to ensure that access control policies are enforced correctly across various scenarios.

## 1. Importance of Testing Permissions

Testing the permission system is critical to:
- **Ensure Security**: Verify that unauthorized access is denied.
- **Validate Policies**: Confirm that policies are interpreted and enforced as intended.
- **Prevent Regressions**: Catch issues introduced by code or policy changes.
- **Simulate Real-World Scenarios**: Test edge cases and complex access patterns that users might encounter.

Cedrina's test suite is structured to cover unit tests for individual components and feature tests for end-to-end scenarios.

## 2. Test Structure in Cedrina

Tests related to permissions are organized in two main directories:

- **Unit Tests**: Located in `tests/unit/permissions/`, these focus on individual components like the Casbin enforcer, policy parsing, and dependency logic.
- **Feature Tests**: Located in `tests/feature/`, these simulate API requests with different user roles, policies, and scenarios to validate the integrated behavior of the permission system.

## 3. Setting Up Test Environment

Before running tests, ensure the test environment mirrors production as closely as possible:

- **Database**: Use a separate test database to avoid data contamination. This is configured in `tests/conftest.py` with fixtures for database setup and teardown.
- **Policy Loading**: Tests load policies from a test-specific `policy.csv` or mock the enforcer to simulate specific policy sets.
- **Mocking Dependencies**: Use mocking to simulate user authentication (`get_current_user`) and enforcer behavior (`get_enforcer`) without relying on actual user data or policy files.

## 4. Writing Unit Tests for Permissions

Unit tests focus on isolated components of the permission system. Key areas to test include:

- **Enforcer Logic**: Test `enforcer.enforce()` with various subject, object, and action combinations to ensure correct policy evaluation (e.g., `test_enforcer.py`).
- **Policy Parsing**: Validate that policies from `policy.csv` or API updates are correctly loaded into the enforcer (e.g., `test_policies.py`).
- **Dependency Injection**: Ensure `get_enforcer` and `get_current_user` return expected objects or mock behaviors (e.g., `test_dependencies.py`).

**Example** from `test_enforcer.py`:
```python
def test_enforcer_basic_rbac(mock_enforcer):
    assert mock_enforcer.enforce('admin', '/api/v1/admin/policies', 'read') == True
    assert mock_enforcer.enforce('user', '/api/v1/admin/policies', 'read') == False
```

## 5. Writing Feature Tests for End-to-End Scenarios

Feature tests simulate real API requests to validate the entire permission flow. Key scenarios to test include:

- **Basic Access**: Test that users with appropriate roles can access endpoints (e.g., `test_admin_access.py`).
- **Access Denial**: Verify that unauthorized users are denied access with HTTP 403 (e.g., `test_user_access.py`).
- **Dynamic Updates**: Test policy changes during runtime and their immediate effect (e.g., `test_dynamic_policy_update_during_user_session.py`).
- **Complex Scenarios**: Test ABAC, time-based access, multi-role conflicts, and temporary access grants (e.g., `test_time_based_access_restrictions.py`, `test_multi_role_user_access_conflict.py`).

**Example** from `test_user_access.py`:
```python
@pytest.mark.asyncio
async def test_user_access_to_denied_resource(client, regular_user_token):
    headers = {'Authorization': f'Bearer {regular_user_token}'}
    response = await client.get('/api/v1/admin/policies', headers=headers)
    assert response.status_code == 403
```

## 6. Mocking for Controlled Testing

Mocking is extensively used in Cedrina's tests to control the environment:

- **Mock get_current_user**: Simulate different user roles or attributes without actual authentication.
  ```python
  async def mock_get_current_user():
      return User(username='test_admin', role=Role.ADMIN)
  mocker.patch('src.core.dependencies.auth.get_current_user', mock_get_current_user)
  ```
- **Mock get_enforcer**: Simulate specific policy enforcement outcomes.
  ```python
  def mock_enforcer():
      enforcer = MagicMock()
      enforcer.enforce.side_effect = lambda sub, obj, act: sub == 'admin' and obj.startswith('/api/v1/admin/')
      return enforcer
  mocker.patch('src.permissions.enforcer.get_enforcer', mock_enforcer)
  ```

## 7. Test Coverage and Metrics

- **Coverage Goals**: Aim for high test coverage (90%+) for permission-related code, especially for enforcer logic, policy management, and API endpoints.
- **Coverage Tools**: Use `pytest-cov` to measure coverage. Run `pytest --cov=src.permissions` to check coverage for the permissions module.
- **Focus Areas**: Ensure coverage for edge cases (e.g., no policy, conflicting policies) and error paths (e.g., permission denied responses).

## 8. Validation Techniques

Beyond automated tests, validate the permission system through:

- **Manual Testing**: Perform manual API calls with tools like Postman or curl to simulate user access with different roles.
- **Policy Simulation**: Before deploying new policies, simulate their impact in a staging environment to predict access changes.
- **Audit Logs Review**: After policy updates, review audit logs to confirm changes were applied as intended.

## 9. Common Test Scenarios to Include

Ensure your test suite covers:
- **Role-Based Access**: Admin vs. regular user access to protected endpoints.
- **Attribute-Based Access**: Access based on user attributes like department or location.
- **Time-Based Restrictions**: Policies that vary by time of day or date.
- **Policy Conflicts**: Scenarios where multiple policies apply, testing conflict resolution.
- **Dynamic Policy Changes**: Adding/removing policies during active user sessions.
- **Rate Limiting**: Enforcement of rate limits on policy management endpoints.
- **Error Handling**: Correct HTTP status codes and messages for denied access.

## 10. Best Practices for Testing Permissions

- **Isolation**: Use fixtures to reset database state and policy state between tests to prevent interference (e.g., `database_cleanup` fixture in `conftest.py`).
- **Descriptive Test Names**: Name tests clearly to reflect the scenario (e.g., `test_regular_user_denied_admin_access`).
- **Test Data Variety**: Use a variety of user roles, attributes, and policy configurations to cover all possible access patterns.
- **Continuous Integration (CI)**: Run permission tests in CI pipelines to catch issues early during development.
- **Property-Based Testing**: For critical components like the enforcer, consider property-based testing (e.g., using `hypothesis`) to test with random policy and request combinations.
- **Performance Testing**: Test the performance impact of permission checks under load, especially for endpoints with frequent access.

## 11. Debugging Test Failures

When tests fail:
- **Check Logs**: Review test output for Casbin enforcement decisions (e.g., `Mock enforce: Allowing/Denying access for subject X`).
- **Verify Mock Behavior**: Ensure mocks are set up correctly to simulate the intended user or policy state.
- **Isolate Test**: Run the failing test alone (`pytest -k test_name`) to check if it's an isolation issue with other tests.
- **Review Policy**: Double-check the policy used in the test for syntax or logical errors.

For additional help with common issues encountered during testing, refer to the [Troubleshooting Guide](./troubleshooting.md). 