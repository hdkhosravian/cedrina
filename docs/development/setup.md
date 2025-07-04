# Development Setup

This guide provides detailed instructions for setting up your local development environment for Cedrina.

## Prerequisites

Before setting up your development environment, ensure you have the following software installed:

### Required Software

- **Python 3.12+**: [Download from python.org](https://www.python.org/downloads/)
- **Poetry**: [Installation guide](https://python-poetry.org/docs/#installation)
- **Docker & Docker Compose**: [Download from docker.com](https://www.docker.com/products/docker-desktop/)
- **Git**: [Download from git-scm.com](https://git-scm.com/downloads)

### Optional Software

- **PostgreSQL 16**: For local development without Docker
- **Redis 7.2**: For local development without Docker
- **VS Code**: Recommended IDE with Python extensions
- **Postman/Insomnia**: For API testing

## Quick Setup (Recommended)

The fastest way to get started is using Docker for all services:

```bash
# Clone the repository
git clone https://github.com/hdkhosravian/cedrina.git
cd cedrina

# Start all services with Docker
make run-dev

# Verify the setup
curl http://localhost:8000/api/v1/health
```

## Manual Setup

For development without Docker or for more control over the environment:

### Step 1: Clone and Setup

```bash
# Clone the repository
git clone https://github.com/hdkhosravian/cedrina.git
cd cedrina

# Install Python dependencies
poetry install

# Activate the virtual environment
poetry shell
```

### Step 2: Environment Configuration

```bash
# Copy environment template
cp .env.example .env.development

# Edit the environment file with your settings
nano .env.development
```

Key environment variables for development:

```bash
# Database Configuration
DATABASE_URL=postgresql://cedrina:password@localhost:5432/cedrina_dev
REDIS_URL=redis://localhost:6379/0

# Security Configuration
SECRET_KEY=your-development-secret-key
JWT_PRIVATE_KEY_PATH=./keys/private.pem
JWT_PUBLIC_KEY_PATH=./keys/public.pem

# Application Configuration
DEBUG=True
LOG_LEVEL=DEBUG
DEFAULT_LANGUAGE=en

# Rate Limiting
RATE_LIMIT_ENABLED=True
RATE_LIMIT_STORAGE_URL=redis://localhost:6379/1
```

### Step 3: Database Setup

#### Option A: Using Docker for Databases Only

```bash
# Start only PostgreSQL and Redis
docker-compose up -d postgres redis

# Wait for databases to be ready
sleep 10
```

#### Option B: Local Installation

**PostgreSQL:**
```bash
# macOS (using Homebrew)
brew install postgresql@16
brew services start postgresql@16

# Ubuntu/Debian
sudo apt update
sudo apt install postgresql-16 postgresql-contrib-16
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql
CREATE DATABASE cedrina_dev;
CREATE USER cedrina WITH PASSWORD 'password';
GRANT ALL PRIVILEGES ON DATABASE cedrina_dev TO cedrina;
\q
```

**Redis:**
```bash
# macOS (using Homebrew)
brew install redis
brew services start redis

# Ubuntu/Debian
sudo apt install redis-server
sudo systemctl start redis-server
sudo systemctl enable redis-server
```

### Step 4: JWT Keys Generation

```bash
# Create keys directory
mkdir -p keys

# Generate private key
openssl genrsa -out keys/private.pem 2048

# Generate public key
openssl rsa -in keys/private.pem -pubout -out keys/public.pem

# Set proper permissions
chmod 600 keys/private.pem
chmod 644 keys/public.pem
```

### Step 5: Database Migrations

```bash
# Run database migrations
make db-migrate

# Optional: Seed with test data
make db-seed
```

### Step 6: Start the Application

```bash
# Start the development server
make run-dev-local

# Or using Poetry directly
poetry run uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```

## Development Workflow

### Code Quality Checks

```bash
# Format code
make format

# Lint code
make lint

# Type checking
make type-check

# Security checks
make security-check

# Run all quality checks
make quality-check
```

### Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-cov

# Run specific test categories
poetry run pytest tests/unit/ -v
poetry run pytest tests/integration/ -v
poetry run pytest tests/feature/ -v

# Run tests in parallel
poetry run pytest -n auto

# Run tests with specific markers
poetry run pytest -m "not slow" -v
```

### Database Operations

```bash
# Create new migration
make db-migrate-create msg="Add new table"

# Apply migrations
make db-migrate

# Rollback migrations
make db-rollback

# Reset database
make db-reset

# View migration status
make db-status
```

### Internationalization

```bash
# Extract translatable strings
make i18n-extract

# Compile translations
make i18n-compile

# Update translations
make i18n-update
```

## IDE Configuration

### VS Code Setup

1. **Install Extensions:**
   - Python (Microsoft)
   - Pylance
   - Python Test Explorer
   - Docker
   - REST Client

2. **Workspace Settings** (`.vscode/settings.json`):
```json
{
    "python.defaultInterpreterPath": "./.venv/bin/python",
    "python.testing.pytestEnabled": true,
    "python.testing.pytestArgs": ["tests"],
    "python.formatting.provider": "black",
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": true,
    "python.linting.mypyEnabled": true,
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.organizeImports": true
    }
}
```

3. **Launch Configuration** (`.vscode/launch.json`):
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "FastAPI",
            "type": "python",
            "request": "launch",
            "module": "uvicorn",
            "args": ["src.main:app", "--reload", "--host", "0.0.0.0", "--port", "8000"],
            "env": {
                "PYTHONPATH": "${workspaceFolder}"
            }
        }
    ]
}
```

### PyCharm Setup

1. **Configure Interpreter:**
   - Go to Settings → Project → Python Interpreter
   - Add new interpreter → Poetry Environment
   - Select the project's Poetry environment

2. **Configure Run Configuration:**
   - Add new configuration → Python
   - Script path: `uvicorn`
   - Parameters: `src.main:app --reload --host 0.0.0.0 --port 8000`
   - Environment variables: Add `PYTHONPATH=src`

## Debugging

### Application Logs

```bash
# View application logs
docker-compose logs -f app

# View specific service logs
docker-compose logs -f postgres
docker-compose logs -f redis
```

### Database Debugging

```bash
# Connect to PostgreSQL
docker-compose exec postgres psql -U cedrina -d cedrina_dev

# Or locally
psql -h localhost -U cedrina -d cedrina_dev

# View Redis data
docker-compose exec redis redis-cli
```

### API Testing

```bash
# Test health endpoint
curl http://localhost:8000/api/v1/health

# Test authentication
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "email": "test@example.com", "password": "SecurePass123!"}'

# Test login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "SecurePass123!"}'
```

## Performance Monitoring

### Development Tools

```bash
# Install development dependencies
poetry install --with dev

# Run performance profiling
poetry run python -m cProfile -o profile.stats -m uvicorn src.main:app

# Analyze profile results
poetry run python -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative').print_stats(20)"
```

### Memory Profiling

```bash
# Install memory profiler
poetry add memory-profiler

# Profile memory usage
poetry run python -m memory_profiler src/main.py
```

## Troubleshooting

### Common Issues

1. **Port Already in Use:**
   ```bash
   # Find process using port 8000
   lsof -i :8000
   
   # Kill the process
   kill -9 <PID>
   ```

2. **Database Connection Issues:**
   ```bash
   # Check if PostgreSQL is running
   sudo systemctl status postgresql
   
   # Check connection
   psql -h localhost -U cedrina -d cedrina_dev
   ```

3. **Redis Connection Issues:**
   ```bash
   # Check if Redis is running
   sudo systemctl status redis
   
   # Test connection
   redis-cli ping
   ```

4. **Permission Issues:**
   ```bash
   # Fix JWT key permissions
   chmod 600 keys/private.pem
   chmod 644 keys/public.pem
   ```

5. **Poetry Issues:**
   ```bash
   # Clear Poetry cache
   poetry cache clear . --all
   
   # Reinstall dependencies
   poetry install --sync
   ```

### Environment-Specific Issues

**macOS:**
```bash
# Install additional dependencies
brew install postgresql@16 redis

# Start services
brew services start postgresql@16
brew services start redis
```

**Windows:**
```bash
# Use WSL2 for better compatibility
# Or install PostgreSQL and Redis manually
```

**Linux:**
```bash
# Install system dependencies
sudo apt update
sudo apt install postgresql-16 postgresql-contrib-16 redis-server

# Start services
sudo systemctl start postgresql
sudo systemctl start redis-server
```

## Next Steps

After setting up your development environment:

1. Read the [Quick Start Guide](getting-started/quick-start.md) to understand the basics
2. Explore the [Project Structure](architecture/project-structure.md) to understand the codebase
3. Review the [Testing Guide](development/testing.md) for testing practices
4. Check the [Code Quality Guide](development/code-quality.md) for development standards
5. Explore the [API Documentation](development/api-docs.md) for endpoint usage 