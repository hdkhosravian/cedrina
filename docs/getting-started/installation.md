# Installation Guide

This guide provides detailed instructions for installing and setting up Cedrina on your local development environment.

## Prerequisites

Before installing Cedrina, ensure you have the following software installed:

### Required Software

- **Python 3.12+**: [Download from python.org](https://www.python.org/downloads/)
- **Poetry**: [Installation guide](https://python-poetry.org/docs/#installation)
- **Docker & Docker Compose**: [Download from docker.com](https://www.docker.com/products/docker-desktop/)
- **Git**: [Download from git-scm.com](https://git-scm.com/downloads)

### Optional Software

- **PostgreSQL 16**: For local development without Docker
- **Redis 7.2**: For local development without Docker
- **VS Code**: Recommended IDE with Python extensions

## Installation Methods

### Method 1: Docker Installation (Recommended)

This is the easiest way to get started as it handles all dependencies automatically.

```bash
# Clone the repository
git clone https://github.com/hdkhosravian/cedrina.git
cd cedrina

# Start the application with Docker
make run-dev

# Verify installation
curl http://localhost:8000/api/v1/health
```

### Method 2: Local Installation

For development without Docker, follow these steps:

```bash
# Clone the repository
git clone https://github.com/hdkhosravian/cedrina.git
cd cedrina

# Install Python dependencies
poetry install

# Set up environment variables
cp .env.example .env.development
# Edit .env.development with your local settings

# Start PostgreSQL and Redis (if not using Docker)
# You can use Docker for just the databases:
docker-compose up -d postgres redis

# Run database migrations
make db-migrate

# Start the application
make run-dev-local
```

## Environment Configuration

### Environment Files

Cedrina uses different environment files for different deployment stages:

- `.env.development` - Local development
- `.env.staging` - Staging environment
- `.env.production` - Production environment

### Key Configuration Variables

```bash
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/cedrina
REDIS_URL=redis://localhost:6379/0

# Security Configuration
SECRET_KEY=your-secret-key-here
JWT_ALGORITHM=RS256
JWT_PRIVATE_KEY_PATH=path/to/private.pem
JWT_PUBLIC_KEY_PATH=path/to/public.pem

# Application Configuration
DEBUG=True
LOG_LEVEL=INFO
DEFAULT_LANGUAGE=en

# Rate Limiting
RATE_LIMIT_ENABLED=True
RATE_LIMIT_STORAGE_URL=redis://localhost:6379/1
```

## Verification

After installation, verify that everything is working:

```bash
# Check application health
curl http://localhost:8000/api/v1/health

# Run tests
make test

# Check code quality
make lint
make type-check
```

## Troubleshooting

### Common Issues

1. **Port Conflicts**: If ports 8000, 5432, or 6379 are in use, modify the Docker Compose file or use different ports.

2. **Permission Issues**: On Linux/macOS, you might need to run Docker commands with `sudo`.

3. **Python Version**: Ensure you're using Python 3.12+ by running `python --version`.

4. **Poetry Issues**: If Poetry isn't found, ensure it's in your PATH or reinstall it.

### Getting Help

- Check the [troubleshooting guide](reference/troubleshooting.md)
- Review the [configuration documentation](getting-started/configuration.md)
- Open an issue on GitHub for bugs or feature requests

## Next Steps

After successful installation:

1. Read the [Quick Start Guide](quick-start.md) to understand the basics
2. Explore the [Project Structure](architecture/project-structure.md) to understand the codebase
3. Review the [Development Setup](development/setup.md) for development workflows
4. Check the [Testing Guide](development/testing.md) for testing practices 