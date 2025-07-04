# Quick Start Guide

Get Cedrina up and running in minutes with this quick start guide.

## Prerequisites

- **Python 3.12+**: `python --version`
- **Poetry**: `poetry --version`
- **Docker**: `docker --version`
- **Git**: `git --version`

## 1. Clone and Setup

```bash
# Clone the repository
git clone https://github.com/hdkhosravian/cedrina.git
cd cedrina

# Install dependencies
poetry install

# Copy environment file
cp .env.development .env
```

## 2. Configure Environment

Edit `.env` with your settings:

```bash
# Generate a secure secret key
SECRET_KEY=$(openssl rand -base64 32)

# Update .env with your values
SECRET_KEY=your_generated_secret_key
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_password
POSTGRES_DB=cedrina_dev
```

## 3. Start Services

### Option A: Docker (Recommended)

```bash
# Start all services (app, PostgreSQL, Redis)
make run-dev

# Or using docker-compose directly
docker-compose up -d
```

### Option B: Local Services

```bash
# Start PostgreSQL and Redis locally
# Then run the application
make run-dev-local
```

## 4. Verify Installation

```bash
# Check health endpoint
curl http://localhost:8000/api/v1/health

# Expected response:
{
  "status": "ok",
  "env": "development",
  "message": "System is operational"
}
```

## 5. Access the Application

- **API**: http://localhost:8000/api/v1/
- **Health Check**: http://localhost:8000/api/v1/health
- **WebSocket**: ws://localhost:8000/ws/health
- **Documentation**: http://localhost:8000/docs (if DEBUG=true)

## 6. Run Tests

```bash
# Run all tests
make test

# Run with coverage
make test-cov

# Run specific test categories
poetry run pytest tests/unit/ -v
poetry run pytest tests/integration/ -v
```

## 7. Development Workflow

```bash
# Format code
make format

# Lint code
make lint

# Run pre-commit hooks
git add .
git commit -m "Your commit message"
```

## Quick Commands Reference

| Command | Description |
|---------|-------------|
| `make run-dev` | Start development environment with Docker |
| `make run-dev-local` | Start app locally (requires local PostgreSQL/Redis) |
| `make test` | Run test suite |
| `make format` | Format code with black and ruff |
| `make lint` | Lint code with ruff and mypy |
| `make db-migrate` | Apply database migrations |
| `make compile-translations` | Compile i18n translations |

## Next Steps

1. **Explore the Architecture**: Read [Project Structure](../architecture/project-structure.md)
2. **Understand Authentication**: Check [Authentication System](../features/authentication/README.md)
3. **Configure Production**: See [Production Setup](../deployment/production.md)
4. **Run Tests**: Follow [Testing Guide](../development/testing.md)

## Troubleshooting

### Common Issues

**Database Connection Error**
```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# Check logs
docker-compose logs postgres
```

**Port Already in Use**
```bash
# Check what's using port 8000
lsof -i :8000

# Kill the process or change port in .env
API_PORT=8001
```

**Permission Denied**
```bash
# Fix file permissions
chmod +x entrypoint.sh
chmod +x scripts/*.sh
```

### Getting Help

- **Documentation**: Check the [troubleshooting guide](../reference/troubleshooting.md)
- **Issues**: Create an issue on GitHub
- **Logs**: Check application logs with `docker-compose logs app`

## Environment Variables

Key environment variables for development:

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Application secret key | Required |
| `POSTGRES_HOST` | PostgreSQL host | `postgres` (Docker) |
| `POSTGRES_DB` | Database name | `cedrina_dev` |
| `REDIS_HOST` | Redis host | `redis` (Docker) |
| `DEBUG` | Debug mode | `false` |
| `LOG_LEVEL` | Logging level | `INFO` |

## What's Next?

You now have a working Cedrina application! Here's what you can do next:

1. **Explore the API**: Try the authentication endpoints
2. **Add Features**: Follow the architecture patterns to add new functionality
3. **Deploy**: Set up staging and production environments
4. **Contribute**: Check the contribution guidelines

For detailed information, explore the rest of the documentation sections. 