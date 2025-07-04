# Code Quality

Cedrina enforces high code quality standards through automated tools and manual review processes. This ensures maintainable, secure, and consistent code across the project.

## Quality Standards

### Core Principles

- **Clean Code**: Readable, self-documenting code with clear intent
- **SOLID Principles**: Single responsibility, open/closed, Liskov substitution, interface segregation, dependency inversion
- **Domain-Driven Design**: Ubiquitous language, bounded contexts, and domain modeling
- **Test-Driven Development**: Write tests first, maintain 95%+ coverage
- **Security First**: Input validation, secure defaults, and security scanning

### Code Style Guidelines

- **Naming**: Use intention-revealing names that reflect domain concepts
- **Functions**: Keep functions small (under 15 lines) and focused
- **Classes**: Single responsibility, high cohesion, low coupling
- **Comments**: Explain "why" not "what", use docstrings for public APIs
- **Formatting**: Consistent indentation, spacing, and structure

## Automated Quality Tools

### Code Formatting

#### Black

Black is used for automatic code formatting with zero configuration:

```bash
# Format all Python files
make format

# Format specific files
poetry run black src/ tests/

# Check formatting without changes
poetry run black --check src/ tests/
```

**Configuration** (`.pyproject.toml`):
```toml
[tool.black]
line-length = 88
target-version = ['py312']
include = '\.pyi?$'
extend-exclude = '''
/(
  # directories
  \.eggs
  | \.git
  | \.hg
  | \.mypy_cache
  | \.tox
  | \.venv
  | build
  | dist
)/
'''
```

#### isort

isort automatically sorts and organizes imports:

```bash
# Sort imports
make format

# Sort imports in specific files
poetry run isort src/ tests/

# Check import sorting
poetry run isort --check-only src/ tests/
```

**Configuration** (`.pyproject.toml`):
```toml
[tool.isort]
profile = "black"
multi_line_output = 3
line_length = 88
known_first_party = ["src"]
known_third_party = ["fastapi", "pydantic", "sqlalchemy"]
```

### Code Linting

#### Flake8

Flake8 checks for style violations and potential errors:

```bash
# Run flake8
make lint

# Run with specific configuration
poetry run flake8 src/ tests/

# Generate report
poetry run flake8 --format=html --htmldir=flake8-report src/ tests/
```

**Configuration** (`.flake8`):
```ini
[flake8]
max-line-length = 88
extend-ignore = E203, W503
exclude = 
    .git,
    __pycache__,
    .venv,
    build,
    dist,
    *.egg-info
per-file-ignores =
    __init__.py:F401
    tests/*:S101,S105,S106,S107
```

#### Bandit

Bandit performs security linting to identify common security issues:

```bash
# Run security checks
make security-check

# Run bandit with specific configuration
poetry run bandit -r src/ -f json -o bandit-report.json

# Run with severity levels
poetry run bandit -r src/ -ll -ii
```

**Configuration** (`.bandit`):
```ini
[bandit]
exclude_dirs = tests
skips = B101,B601
```

### Type Checking

#### MyPy

MyPy provides static type checking for Python:

```bash
# Run type checking
make type-check

# Run with specific configuration
poetry run mypy src/

# Generate type coverage report
poetry run mypy --html-report mypy-report src/
```

**Configuration** (`.mypy.ini`):
```ini
[mypy]
python_version = 3.12
warn_return_any = True
warn_unused_configs = True
disallow_untyped_defs = True
disallow_incomplete_defs = True
check_untyped_defs = True
disallow_untyped_decorators = True
no_implicit_optional = True
warn_redundant_casts = True
warn_unused_ignores = True
warn_no_return = True
warn_unreachable = True
strict_equality = True

[mypy.plugins.pydantic.*]
init_forbid_extra = True
init_typed = True
warn_required_dynamic_aliases = True
warn_untyped_fields = True
```

### Pre-commit Hooks

Pre-commit hooks automatically run quality checks before commits:

```bash
# Install pre-commit hooks
make install-hooks

# Run hooks manually
make pre-commit

# Run specific hook
poetry run pre-commit run black --all-files
```

**Configuration** (`.pre-commit-config.yaml`):
```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-merge-conflict

  - repo: https://github.com/psf/black
    rev: 23.3.0
    hooks:
      - id: black

  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort

  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.3.0
    hooks:
      - id: mypy
        additional_dependencies: [types-all]
```

## Testing Standards

### Coverage Requirements

- **Minimum Coverage**: 95% for all code
- **Critical Paths**: 100% coverage for authentication, security, and core business logic
- **Integration Tests**: All API endpoints must have integration tests
- **Performance Tests**: Critical endpoints must have performance benchmarks

### Test Structure

```bash
tests/
├── unit/                    # Unit tests (70-80% of tests)
│   ├── domain/             # Domain logic tests
│   ├── services/           # Service layer tests
│   └── adapters/           # Adapter layer tests
├── integration/            # Integration tests (15-20% of tests)
│   ├── api/               # API endpoint tests
│   ├── database/          # Database integration tests
│   └── external/          # External service tests
└── feature/               # Feature tests (5-10% of tests)
    ├── auth/              # Authentication flows
    ├── rate_limiting/     # Rate limiting scenarios
    └── permissions/       # Permission scenarios
```

### Test Quality Standards

```python
# Example of high-quality test
import pytest
from unittest.mock import AsyncMock, patch

from src.domain.services.authentication.user_authentication_service import (
    UserAuthenticationService,
)
from src.domain.value_objects.username import Username
from src.domain.value_objects.password import Password


class TestUserAuthenticationService:
    """Test suite for UserAuthenticationService following TDD principles."""

    @pytest.fixture
    def mock_user_repository(self):
        """Provide mock user repository for testing."""
        return AsyncMock()

    @pytest.fixture
    def mock_event_publisher(self):
        """Provide mock event publisher for testing."""
        return AsyncMock()

    @pytest.fixture
    def auth_service(self, mock_user_repository, mock_event_publisher):
        """Provide UserAuthenticationService instance for testing."""
        return UserAuthenticationService(
            user_repository=mock_user_repository,
            event_publisher=mock_event_publisher,
        )

    @pytest.mark.asyncio
    async def test_authenticate_user_with_valid_credentials_succeeds(
        self, auth_service, mock_user_repository, mock_event_publisher
    ):
        """Test successful authentication with valid credentials."""
        # Arrange
        username = Username("testuser")
        password = Password("SecurePass123!")
        user = AsyncMock()
        user.id = 1
        user.username = "testuser"
        user.is_active = True
        
        mock_user_repository.find_by_username.return_value = user
        mock_user_repository.verify_password.return_value = True

        # Act
        result = await auth_service.authenticate_user(
            username=username,
            password=password,
            language="en",
            client_ip="127.0.0.1",
            user_agent="test-agent",
            correlation_id="test-correlation-id",
        )

        # Assert
        assert result == user
        mock_user_repository.find_by_username.assert_called_once_with(username)
        mock_event_publisher.publish.assert_called_once()
        
        # Verify event was published
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert published_event.user_id == user.id
        assert published_event.username == str(username)
```

## Code Review Process

### Review Checklist

#### Functionality
- [ ] Does the code implement the intended functionality?
- [ ] Are edge cases handled appropriately?
- [ ] Are error conditions properly managed?
- [ ] Does the code follow the existing patterns?

#### Code Quality
- [ ] Is the code readable and self-documenting?
- [ ] Are functions and classes appropriately sized?
- [ ] Are variable and function names intention-revealing?
- [ ] Is there appropriate separation of concerns?

#### Testing
- [ ] Are there sufficient unit tests?
- [ ] Do tests cover edge cases and error conditions?
- [ ] Are integration tests included where appropriate?
- [ ] Does the test coverage meet requirements?

#### Security
- [ ] Are inputs properly validated?
- [ ] Are there any potential security vulnerabilities?
- [ ] Is sensitive data handled appropriately?
- [ ] Are authentication and authorization checks in place?

#### Performance
- [ ] Are there any obvious performance issues?
- [ ] Are database queries optimized?
- [ ] Is caching used appropriately?
- [ ] Are there any memory leaks or resource issues?

### Review Guidelines

1. **Be Constructive**: Focus on the code, not the person
2. **Explain Why**: Provide context for suggestions
3. **Suggest Alternatives**: Offer specific solutions
4. **Check for Patterns**: Ensure consistency with existing code
5. **Verify Tests**: Ensure adequate test coverage

## Continuous Integration

### GitHub Actions Workflow

```yaml
# .github/workflows/quality.yml
name: Code Quality

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  quality:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.12'
    
    - name: Install Poetry
      uses: snok/install-poetry@v1
      with:
        version: latest
    
    - name: Install dependencies
      run: poetry install
    
    - name: Run code formatting check
      run: poetry run black --check src/ tests/
    
    - name: Run import sorting check
      run: poetry run isort --check-only src/ tests/
    
    - name: Run linting
      run: poetry run flake8 src/ tests/
    
    - name: Run type checking
      run: poetry run mypy src/
    
    - name: Run security checks
      run: poetry run bandit -r src/ -f json -o bandit-report.json
    
    - name: Run tests with coverage
      run: poetry run pytest --cov=src --cov-report=xml --cov-report=html
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
```

## Quality Metrics

### Code Metrics

- **Cyclomatic Complexity**: Keep functions under 10
- **Maintainability Index**: Aim for 65+ (high maintainability)
- **Technical Debt**: Track and reduce technical debt
- **Code Duplication**: Keep duplication under 5%

### Performance Metrics

- **Response Time**: API endpoints under 200ms for 95th percentile
- **Throughput**: Handle 1000+ requests per second
- **Memory Usage**: Monitor for memory leaks
- **Database Performance**: Query execution time under 100ms

### Security Metrics

- **Vulnerability Scan**: Zero high/critical vulnerabilities
- **Security Coverage**: 100% coverage of security-critical code
- **Dependency Updates**: Keep dependencies up to date
- **Security Headers**: All security headers properly configured

## Tools and IDE Integration

### VS Code Extensions

```json
{
    "recommendations": [
        "ms-python.python",
        "ms-python.pylance",
        "ms-python.black-formatter",
        "ms-python.isort",
        "ms-python.flake8",
        "ms-python.mypy-type-checker",
        "streetsidesoftware.code-spell-checker",
        "yzhang.markdown-all-in-one"
    ]
}
```

### PyCharm Configuration

1. **External Tools**:
   - Black: `$ProjectFileDir$/.venv/bin/black $FilePath$`
   - isort: `$ProjectFileDir$/.venv/bin/isort $FilePath$`
   - flake8: `$ProjectFileDir$/.venv/bin/flake8 $FilePath$`

2. **File Watchers**:
   - Auto-format on save with Black
   - Auto-sort imports with isort

## Best Practices

### Code Organization

1. **Follow DDD Structure**: Organize code by domain concepts
2. **Use Clear Abstractions**: Interfaces for dependencies
3. **Keep Dependencies Inverted**: Depend on abstractions, not concretions
4. **Separate Concerns**: Business logic separate from infrastructure

### Documentation

1. **Docstrings**: All public APIs must have docstrings
2. **Type Hints**: Use type hints for all function parameters and returns
3. **README Updates**: Keep documentation current with code changes
4. **Architecture Decisions**: Document significant design decisions

### Error Handling

1. **Domain Exceptions**: Use domain-specific exceptions
2. **Graceful Degradation**: Handle errors gracefully
3. **Logging**: Log errors with appropriate context
4. **User Feedback**: Provide meaningful error messages

## Next Steps

- Review the [Testing Guide](testing.md) for detailed testing practices
- Check the [API Documentation](api-docs.md) for endpoint standards
- Explore the [Architecture Documentation](architecture/application-architecture.md) for design patterns
- Read the [Contributing Guide](../../CONTRIBUTING.md) for contribution standards 