# Testing Guide

## Overview

Cedrina employs a comprehensive testing strategy with **95%+ test coverage** to ensure code reliability, maintainability, and correctness. The testing approach follows the **test pyramid** principle with unit tests as the foundation, integration tests for component interactions, and feature tests for end-to-end workflows.

## Testing Strategy

### Test Pyramid

```
    ┌─────────────┐
    │   Feature   │  ← 5-10% (End-to-end workflows)
    │    Tests    │
    └─────────────┘
         │
    ┌─────────────┐
    │Integration  │  ← 15-20% (Component interactions)
    │   Tests     │
    └─────────────┘
         │
    ┌─────────────┐
    │   Unit      │  ← 70-80% (Individual components)
    │   Tests     │
    └─────────────┘
```

### Test Categories

1. **Unit Tests** (70-80%): Test individual components in isolation
2. **Integration Tests** (15-20%): Test component interactions
3. **Feature Tests** (5-10%): Test complete user workflows
4. **Performance Tests**: Load and stress testing

## Test Structure

```
tests/
├── conftest.py                    # Test configuration and fixtures
├── unit/                          # Unit tests
│   ├── adapters/                  # API and WebSocket tests
│   │   ├── api/
│   │   │   └── v1/
│   │   │       ├── auth/          # Authentication endpoint tests
│   │   │       └── test_health.py # Health endpoint tests
│   │   └── test_websockets.py     # WebSocket tests
│   ├── core/                      # Core functionality tests
│   │   ├── rate_limiting/         # Rate limiting tests
│   │   ├── test_circuit_breaker.py
│   │   ├── test_exceptions.py
│   │   └── test_metrics.py
│   ├── domain/                    # Domain logic tests
│   │   ├── entities/              # Entity tests
│   │   ├── services/              # Domain service tests
│   │   ├── value_objects/         # Value object tests
│   │   ├── validation/            # Validation tests
│   │   └── security/              # Security tests
│   ├── infrastructure/            # Infrastructure tests
│   │   ├── database/              # Database tests
│   │   ├── repositories/          # Repository tests
│   │   └── services/              # External service tests
│   └── permissions/               # Authorization tests
├── integration/                   # Integration tests
│   ├── test_password_reset_clean_architecture.py
│   ├── test_ratelimit.py
│   ├── test_security_patterns_integration.py
│   └── test_server_startup.py
├── feature/                       # Feature tests
│   ├── auth/                      # Authentication workflows
│   ├── rate_limiting/             # Rate limiting scenarios
│   │   └── real_world_scenarios/  # Real-world use cases
│   └── test_user_access.py        # User access workflows
├── performance/                   # Performance tests
│   └── test_rate_limiting_performance.py
└── factories/                     # Test data factories
    ├── user.py                    # User factory
    ├── token.py                   # Token factory
    └── oauth.py                   # OAuth factory
```

## Running Tests

### Basic Commands

```bash
# Run all tests
make test

# Run with coverage
make test-cov

# Run specific test categories
poetry run pytest tests/unit/ -v
poetry run pytest tests/integration/ -v
poetry run pytest tests/feature/ -v
poetry run pytest tests/performance/ -v

# Run with specific markers
poetry run pytest -m unit -v
poetry run pytest -m integration -v
poetry run pytest -m feature -v
poetry run pytest -m performance -v
```

### Advanced Commands

```bash
# Run tests with detailed output
poetry run pytest -v --tb=long

# Run tests and stop on first failure
poetry run pytest -x

# Run tests in parallel
poetry run pytest -n auto

# Run tests with specific pattern
poetry run pytest tests/unit/adapters/api/v1/auth/ -v

# Run tests with coverage and generate HTML report
poetry run pytest --cov=src --cov-report=html
```

## Test Configuration

### pytest Configuration (`pyproject.toml`)

```toml
[tool.pytest.ini_options]
pythonpath = ["src"]
testpaths = ["tests"]
python_files = ["test_*.py", "*_test.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
addopts = [
    "--strict-markers",
    "--strict-config",
    "--verbose",
    "--tb=short",
    "--cov=src",
    "--cov-report=term-missing",
    "--cov-report=html:htmlcov",
    "--cov-fail-under=95"
]
markers = [
    "unit: Unit tests",
    "integration: Integration tests", 
    "feature: Feature tests",
    "performance: Performance tests",
    "slow: Slow running tests"
]
```

### Test Environment

Tests run in a controlled environment with:

- **Database Isolation**: Each test gets a clean database state
- **Redis Isolation**: Separate Redis instance for testing
- **Mocked External Services**: External APIs are mocked
- **Test Data Factories**: Consistent test data generation

## Test Fixtures

### Database Fixtures (`tests/conftest.py`)

```python
@pytest.fixture(autouse=True)
def clean_database():
    """Clean database before and after each test."""
    # Setup: Create tables
    create_db_and_tables()
    
    yield
    
    # Teardown: Clean all tables
    with get_db_session() as session:
        for table in reversed(SQLModel.metadata.sorted_tables):
            session.execute(table.delete())
        session.commit()
```

### Authentication Fixtures

```python
@pytest.fixture
def authenticated_user():
    """Create and return an authenticated user."""
    user = UserFactory()
    token = create_access_token(user)
    return {"user": user, "token": token}

@pytest.fixture
def admin_user():
    """Create and return an admin user."""
    user = UserFactory(is_admin=True)
    token = create_access_token(user)
    return {"user": user, "token": token}
```

## Writing Tests

### Unit Test Example

```python
import pytest
from src.domain.services.authentication.user_authentication import UserAuthenticationService
from src.domain.exceptions import AuthenticationError
from tests.factories.user import UserFactory

class TestUserAuthenticationService:
    """Test user authentication service."""
    
    def test_authenticate_user_success(self, db_session):
        """Test successful user authentication."""
        # Arrange
        user = UserFactory()
        service = UserAuthenticationService(db_session)
        
        # Act
        result = service.authenticate_user(user.username, "password123")
        
        # Assert
        assert result.id == user.id
        assert result.username == user.username
    
    def test_authenticate_user_invalid_credentials(self, db_session):
        """Test authentication with invalid credentials."""
        # Arrange
        user = UserFactory()
        service = UserAuthenticationService(db_session)
        
        # Act & Assert
        with pytest.raises(AuthenticationError, match="Invalid credentials"):
            service.authenticate_user(user.username, "wrongpassword")
```

### Integration Test Example

```python
import pytest
from fastapi.testclient import TestClient
from src.main import app

class TestAuthenticationAPI:
    """Test authentication API endpoints."""
    
    def test_user_registration_success(self, client: TestClient):
        """Test successful user registration."""
        # Arrange
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "SecurePass123!"
        }
        
        # Act
        response = client.post("/api/v1/auth/register", json=user_data)
        
        # Assert
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == user_data["username"]
        assert data["email"] == user_data["email"]
        assert "id" in data
    
    def test_user_login_success(self, client: TestClient, user_factory):
        """Test successful user login."""
        # Arrange
        user = user_factory(password="SecurePass123!")
        login_data = {
            "username": user.username,
            "password": "SecurePass123!"
        }
        
        # Act
        response = client.post("/api/v1/auth/login", json=login_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
```

### Feature Test Example

```python
import pytest
from fastapi.testclient import TestClient

class TestPasswordChangeWorkflow:
    """Test complete password change workflow."""
    
    def test_password_change_complete_flow(self, client: TestClient, authenticated_user):
        """Test complete password change workflow."""
        # Arrange
        user = authenticated_user["user"]
        token = authenticated_user["token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Step 1: Request password change
        change_data = {
            "old_password": "SecurePass123!",
            "new_password": "NewSecurePass456!"
        }
        
        # Act
        response = client.put(
            "/api/v1/auth/change-password",
            json=change_data,
            headers=headers
        )
        
        # Assert
        assert response.status_code == 200
        
        # Step 2: Verify new password works
        login_data = {
            "username": user.username,
            "password": "NewSecurePass456!"
        }
        
        login_response = client.post("/api/v1/auth/login", json=login_data)
        assert login_response.status_code == 200
```

## Test Data Factories

### User Factory (`tests/factories/user.py`)

```python
import factory
from src.domain.entities.user import User
from src.domain.services.auth.password_encryption import hash_password

class UserFactory(factory.Factory):
    """Factory for creating test users."""
    
    class Meta:
        model = User
    
    username = factory.Sequence(lambda n: f"user{n}")
    email = factory.LazyAttribute(lambda obj: f"{obj.username}@example.com")
    hashed_password = factory.LazyFunction(lambda: hash_password("SecurePass123!"))
    is_active = True
    is_admin = False
```

### Token Factory (`tests/factories/token.py`)

```python
import factory
from src.domain.value_objects.jwt_token import create_access_token
from tests.factories.user import UserFactory

def create_test_token(user=None):
    """Create a test JWT token."""
    if user is None:
        user = UserFactory()
    return create_access_token(user)
```

## Performance Testing

### Rate Limiting Performance Test

```python
import pytest
import asyncio
from fastapi.testclient import TestClient
from src.main import app

class TestRateLimitingPerformance:
    """Test rate limiting performance under load."""
    
    def test_rate_limiting_under_load(self, client: TestClient):
        """Test rate limiting performance under concurrent load."""
        # Arrange
        concurrent_requests = 100
        endpoint = "/api/v1/auth/login"
        
        # Act
        async def make_request():
            return client.post(endpoint, json={
                "username": "testuser",
                "password": "password123"
            })
        
        # Execute concurrent requests
        loop = asyncio.get_event_loop()
        tasks = [make_request() for _ in range(concurrent_requests)]
        responses = loop.run_until_complete(asyncio.gather(*tasks))
        
        # Assert
        rate_limited_count = sum(1 for r in responses if r.status_code == 429)
        assert rate_limited_count > 0  # Some requests should be rate limited
        assert rate_limited_count < concurrent_requests  # Not all should be blocked
```

## Test Coverage

### Coverage Requirements

- **Minimum Coverage**: 95%
- **Critical Paths**: 100% coverage required
- **Domain Logic**: 100% coverage required
- **API Endpoints**: 100% coverage required

### Coverage Report

```bash
# Generate coverage report
poetry run pytest --cov=src --cov-report=html

# View coverage report
open htmlcov/index.html
```

## Best Practices

### 1. **Test Naming**
- Use descriptive test names that explain the scenario
- Follow the pattern: `test_[method]_[scenario]_[expected_result]`

### 2. **Arrange-Act-Assert Pattern**
```python
def test_user_creation_success(self):
    # Arrange
    user_data = {"username": "testuser", "email": "test@example.com"}
    
    # Act
    user = User(**user_data)
    
    # Assert
    assert user.username == "testuser"
    assert user.email == "test@example.com"
```

### 3. **Test Isolation**
- Each test should be independent
- Use fixtures for setup and teardown
- Clean up after each test

### 4. **Mock External Dependencies**
```python
@patch("src.infrastructure.services.email_service.send_email")
def test_password_reset_sends_email(self, mock_send_email):
    """Test that password reset sends email."""
    # Arrange
    mock_send_email.return_value = True
    
    # Act
    result = password_reset_service.send_reset_email("user@example.com")
    
    # Assert
    assert result is True
    mock_send_email.assert_called_once()
```

### 5. **Test Data Management**
- Use factories for consistent test data
- Avoid hardcoded test data
- Use realistic but safe test data

## Continuous Integration

### GitHub Actions Workflow

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      redis:
        image: redis:7.2
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.12'
      - run: pip install poetry
      - run: poetry install
      - run: poetry run pytest --cov=src --cov-fail-under=95
```

## Troubleshooting

### Common Issues

**Database Connection Errors**
```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# Check database logs
docker-compose logs postgres
```

**Test Timeout Issues**
```bash
# Increase timeout for slow tests
poetry run pytest --timeout=300
```

**Coverage Issues**
```bash
# Check which lines are not covered
poetry run pytest --cov=src --cov-report=term-missing
```

### Debugging Tests

```python
# Add debug prints
def test_debug_example(self):
    print("Debug: Starting test")
    result = some_function()
    print(f"Debug: Result is {result}")
    assert result is not None
```

This testing strategy ensures that Cedrina maintains high code quality, reliability, and confidence in the codebase through comprehensive test coverage and well-structured test organization. 