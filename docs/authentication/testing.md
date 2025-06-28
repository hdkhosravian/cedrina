# Authentication System Testing

## Overview
The Cedrina authentication system includes a comprehensive test suite to ensure the reliability, security, and correctness of its components. Tests are organized into unit tests for individual services and integration tests for API endpoints, covering both happy paths and edge cases. This document outlines the testing strategy, structure, and execution process for the authentication system.

## Testing Strategy

- **Unit Tests**: Focus on individual components (e.g., services like `UserAuthenticationService`, `TokenService`) in isolation, mocking dependencies to test logic.
- **Integration Tests**: Validate the interaction between components, particularly API endpoints, database, and external services.
- **Edge Cases**: Test for invalid inputs, expired tokens, duplicate users, password policy violations, and rate limiting.
- **Security Tests**: Ensure protection against common vulnerabilities like brute force attacks (via rate limiting) and token theft (via rotation).
- **Coverage**: Aim for high test coverage, enforced via `pytest --cov` to identify untested code paths.

## Test Structure
Tests are located in the `tests/` directory, mirroring the source structure:

- **Unit Tests**:
  - `tests/unit/services/auth/`: Tests for authentication services.
    - `test_user_authentication.py`: Tests `UserAuthenticationService` for login and registration.
    - `test_change_password.py`: Tests `UserAuthenticationService.change_password()` method with comprehensive security validation.
    - `test_oauth.py`: Tests `OAuthService` for provider authentication.
    - `test_token.py`: Tests `TokenService` for JWT creation and validation.
    - `test_session.py`: Tests `SessionService` for session management.
  - `tests/unit/adapters/api/auth/`: Tests for API endpoint logic.
    - `test_auth_endpoints.py`: Tests registration, login, and OAuth endpoints with mocked services.
- **Integration Tests**:
  - `tests/integration/api/auth/`: End-to-end tests for API endpoints (to be expanded).
  - `tests/feature/auth/`: Feature tests for complete authentication flows.
    - `test_change_password_api.py`: Comprehensive integration tests for the change password API endpoint.
- **Factories**:
  - `tests/factories/`: Faker-based factories for generating test data.
    - `user.py`: Factory for `User` entities and related schemas.
    - `token.py`: Factory for token-related data.
    - `oauth.py`: Factory for OAuth profiles and tokens.

## Test Data Generation
Tests utilize the `faker` library to generate realistic test data, ensuring varied and robust test scenarios. Factories in `tests/factories/` provide reusable methods to create:

- User data with valid and invalid credentials.
- OAuth tokens and profiles for different providers.
- JWT tokens with customizable expiration and claims.

This approach minimizes hardcoded data, improves test maintainability, and covers edge cases like special characters in usernames or emails.

## Running Tests

### Prerequisites
- **Poetry**: Ensure dependencies are installed (`poetry install`).
- **Docker**: For integration tests requiring PostgreSQL and Redis (optional for unit tests).
- **Environment**: `.env.development` with test configurations.

### Commands
- **Run All Tests with Coverage**:
  ```bash
  poetry run pytest --cov=src --cov-report=html
  ```
  View coverage report:
  ```bash
  open htmlcov/index.html
  ```
- **Run Specific Test File**:
  ```bash
  poetry run pytest tests/unit/adapters/api/auth/test_auth_endpoints.py
  ```
- **Run with Docker** (for integration tests):
  ```bash
  make test
  ```

## Key Test Scenarios

### UserAuthenticationService
- Valid and invalid login attempts.
- Registration with duplicate username/email.
- Password policy enforcement (length, character types).
- **Change Password**: Comprehensive security validation including old password verification, password policy enforcement, and password reuse prevention.

### OAuthService
- Authentication with valid and expired OAuth tokens.
- Linking existing users and creating new ones.
- Handling missing or invalid user info from providers.

### TokenService
- JWT creation with correct claims (issuer, audience, expiration).
- Token validation for expired, invalid, or blacklisted tokens.
- Refresh token rotation and revocation.

### SessionService
- Session creation and validation.
- Revocation of sessions and refresh tokens.

### API Endpoints (test_auth_endpoints.py)
- **Registration**: Success (201), duplicate user (409), weak password (422).
- **Login**: Success (200), invalid credentials (401), inactive user (401).
- **OAuth**: Success (200), invalid token (400), expired token (400).

### Change Password API Testing
The change password functionality includes extensive test coverage:

**Unit Tests** (`test_change_password.py`):
- Success scenarios with valid password changes
- Security validation (old password verification)
- Password policy enforcement (all policy requirements)
- Error handling (all exception types)
- Edge cases (empty passwords, None values)
- Database error scenarios

**Integration Tests** (`test_change_password_api.py`):
- API endpoint testing with real HTTP requests
- Authentication token validation
- I18N support for multilingual error messages
- Security headers validation
- Real-world usage scenarios
- All HTTP status code validations (200, 400, 401, 422, 500)
- SQL injection and XSS protection testing
- Unicode password handling
- Admin user access patterns

## Writing Tests
- **Mocking**: Use `unittest.mock` to isolate dependencies (e.g., database, Redis, OAuth providers).
- **Fixtures**: Leverage `pytest` fixtures for reusable setup (e.g., test client, mock services).
- **Factories**: Use Faker factories from `tests/factories/` for test data.
- **Assertions**: Test both expected behavior and error conditions with detailed messages.

## Troubleshooting
- **Test Failures**: Check error messages in `pytest` output. Enable verbose mode with `-v`.
- **Coverage Issues**: If coverage is low, add tests for untested paths shown in `htmlcov/index.html`.
- **Dependency Conflicts**: Ensure `faker`, `pytest`, and `pytest-asyncio` versions are compatible. Update `pyproject.toml` if needed.
  ```bash
  poetry add pytest==8.3.3 pytest-asyncio==0.24.0 faker==37.4.0
  ```
- **Docker Issues**: Ensure containers are running (`docker ps`), and check logs (`docker logs cedrina_app_1`).

## Future Enhancements
- Expand integration tests for full end-to-end flows (client to database).
- Add performance tests for high-load scenarios.
- Implement security penetration tests for vulnerabilities.

This testing framework ensures the Cedrina authentication system remains robust, secure, and reliable as it evolves. 