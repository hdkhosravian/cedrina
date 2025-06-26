# Testing Strategy for Cedrina

## Overview

This document outlines the testing approach for the Cedrina project, a FastAPI-based application. Our goal is to ensure code reliability, maintainability, and correctness through a robust testing framework using `pytest`. We focus on unit tests, integration tests, and ensuring database isolation to prevent test interference.

## Database Isolation in Tests

To ensure that each test runs in a clean environment without interference from previous test data, we use a `pytest` fixture named `clean_database`. This fixture is defined in `tests/conftest.py` and operates as follows:

- **Setup**: Before each test, the fixture creates all necessary database tables using the `create_db_and_tables()` function from `infrastructure.database.database`. This ensures a fresh schema for the test.
- **Teardown**: After each test, the fixture truncates all tables (e.g., `users`, `oauth_profiles`, `sessions`) using a `TRUNCATE TABLE ... CASCADE` SQL command wrapped in SQLAlchemy's `text()` function. This clears all data while preserving the schema structure.
- **Scope and Autouse**: The fixture has a `function` scope, meaning it runs before and after every test function, and `autouse=True` ensures it applies automatically to all tests without needing explicit invocation.

This approach guarantees that no data persists between tests, preventing flaky or interdependent test results. The database isolation is critical for maintaining test reliability, especially for tests involving database operations like user authentication and session management.

## Test Coverage

We aim for high test coverage to validate the functionality of critical components. As of the latest report, the overall coverage is at 90%, with specific focus on:
- **Database Operations**: Coverage for `database.py` is at 83%, testing connectivity, health checks, and session management.
- **Internationalization (i18n)**: Coverage for `i18n.py` is at 87%, testing translation setup and language detection.
- **Core Features**: High coverage for circuit breaker (97%) and metrics (93%) modules.

Areas for further improvement include token handling (74%) and OAuth services (83%).

## Running Tests

To run the test suite with database isolation enabled, use the following command:

```bash
TEST_MODE=true poetry run pytest -v --cov=src
```

- **`TEST_MODE=true`**: Enables test mode, which may adjust application behavior (e.g., skipping certain validations) for testing purposes.
- **`--cov=src`**: Generates a coverage report for the `src` directory to identify untested areas.

## Writing Tests

- **Unit Tests**: Focus on individual functions or classes, mocking dependencies to isolate behavior (e.g., testing translation retrieval in `i18n.py`).
- **Integration Tests**: Validate interactions between components, such as API endpoints with database operations.
- **Fixtures**: Use `pytest` fixtures for reusable setup/teardown logic, like `clean_database` for database isolation.
- **Mocking**: Use `unittest.mock` or `pytest-mock` to simulate external dependencies (e.g., mocking `gettext.translation` for i18n tests).

## Best Practices

- **Isolation**: Ensure tests do not depend on each other by using fixtures like `clean_database`.
- **Coverage**: Aim to cover edge cases, error handling, and main functionality paths.
- **Maintainability**: Write clear, descriptive test names and docstrings to explain the purpose of each test.

For more details on specific tests, refer to the `tests/` directory structure and individual test files. 