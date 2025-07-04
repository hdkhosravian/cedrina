# Configuration Guide

This guide explains all configuration options available in Cedrina, including environment variables, application settings, and deployment configurations.

## Configuration Overview

Cedrina uses a hierarchical configuration system with the following layers:

1. **Environment Variables** - Runtime configuration
2. **Settings Classes** - Type-safe configuration management
3. **Configuration Files** - Static configuration files
4. **Docker Configuration** - Container-specific settings

## Environment Variables

### Database Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DATABASE_URL` | PostgreSQL connection string | - | Yes |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` | No |
| `DATABASE_POOL_SIZE` | Connection pool size | `20` | No |
| `DATABASE_MAX_OVERFLOW` | Max overflow connections | `30` | No |

### Security Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SECRET_KEY` | Application secret key | - | Yes |
| `JWT_ALGORITHM` | JWT signing algorithm | `RS256` | No |
| `JWT_PRIVATE_KEY_PATH` | Path to JWT private key | - | Yes |
| `JWT_PUBLIC_KEY_PATH` | Path to JWT public key | - | Yes |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | Access token expiry | `30` | No |
| `JWT_REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token expiry | `7` | No |

### Application Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DEBUG` | Debug mode | `False` | No |
| `LOG_LEVEL` | Logging level | `INFO` | No |
| `DEFAULT_LANGUAGE` | Default language | `en` | No |
| `PROJECT_NAME` | Application name | `Cedrina` | No |
| `VERSION` | Application version | `1.0.0` | No |

### Rate Limiting Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `RATE_LIMIT_ENABLED` | Enable rate limiting | `True` | No |
| `RATE_LIMIT_STORAGE_URL` | Rate limit storage | `redis://localhost:6379/1` | No |
| `RATE_LIMIT_STRATEGY` | Rate limiting strategy | `fixed-window` | No |
| `RATE_LIMIT_AUTH` | Auth endpoint limit | `10/minute` | No |

### Email Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SMTP_HOST` | SMTP server host | - | Yes |
| `SMTP_PORT` | SMTP server port | `587` | No |
| `SMTP_USERNAME` | SMTP username | - | Yes |
| `SMTP_PASSWORD` | SMTP password | - | Yes |
| `SMTP_USE_TLS` | Use TLS encryption | `True` | No |
| `FROM_EMAIL` | Default sender email | - | Yes |

### OAuth Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | - | No |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | - | No |
| `MICROSOFT_CLIENT_ID` | Microsoft OAuth client ID | - | No |
| `MICROSOFT_CLIENT_SECRET` | Microsoft OAuth client secret | - | No |
| `FACEBOOK_CLIENT_ID` | Facebook OAuth client ID | - | No |
| `FACEBOOK_CLIENT_SECRET` | Facebook OAuth client secret | - | No |

## Settings Classes

Cedrina uses Pydantic settings classes for type-safe configuration management:

### Core Settings

```python
# src/core/config/settings.py
class Settings(BaseSettings):
    # Database settings
    DATABASE_URL: str
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Security settings
    SECRET_KEY: str
    JWT_ALGORITHM: str = "RS256"
    JWT_PRIVATE_KEY_PATH: str
    JWT_PUBLIC_KEY_PATH: str
    
    # Application settings
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    DEFAULT_LANGUAGE: str = "en"
```

### Rate Limiting Settings

```python
# src/core/rate_limiting/config.py
class RateLimitingConfig(BaseSettings):
    enable_rate_limiting: bool = True
    fail_open_on_error: bool = True
    cache_ttl_seconds: int = 300
    
    # Tier-based limits
    free_tier_limit: int = 60
    premium_tier_limit: int = 300
    api_tier_limit: int = 1000
```

## Configuration Files

### Docker Configuration

#### Development Environment

```yaml
# docker-compose.yml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://user:password@postgres:5432/cedrina
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - postgres
      - redis
```

#### Production Environment

```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile.prod
    environment:
      - DEBUG=False
      - LOG_LEVEL=WARNING
    restart: unless-stopped
```

### Alembic Configuration

```ini
# alembic.ini
[alembic]
script_location = alembic
sqlalchemy.url = postgresql://user:password@localhost/cedrina

[loggers]
keys = root,sqlalchemy,alembic
```

## Environment-Specific Configuration

### Development Environment

```bash
# .env.development
DEBUG=True
LOG_LEVEL=DEBUG
DATABASE_URL=postgresql://user:password@localhost:5432/cedrina_dev
REDIS_URL=redis://localhost:6379/0
```

### Staging Environment

```bash
# .env.staging
DEBUG=False
LOG_LEVEL=INFO
DATABASE_URL=postgresql://user:password@staging-db:5432/cedrina_staging
REDIS_URL=redis://staging-redis:6379/0
```

### Production Environment

```bash
# .env.production
DEBUG=False
LOG_LEVEL=WARNING
DATABASE_URL=postgresql://user:password@prod-db:5432/cedrina_prod
REDIS_URL=redis://prod-redis:6379/0
```

## Security Configuration

### JWT Key Generation

Generate RSA key pair for JWT signing:

```bash
# Generate private key
openssl genrsa -out private.pem 2048

# Generate public key
openssl rsa -in private.pem -pubout -out public.pem

# Set permissions
chmod 600 private.pem
chmod 644 public.pem
```

### Environment Variable Security

```bash
# Use strong, random secret key
SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")

# Store sensitive data in environment variables
export DATABASE_PASSWORD="your-secure-password"
export JWT_PRIVATE_KEY_PATH="/path/to/private.pem"
```

## Configuration Validation

Cedrina validates configuration at startup:

```python
# Configuration validation example
try:
    settings = Settings()
    settings.validate()
except ValidationError as e:
    logger.error(f"Configuration validation failed: {e}")
    sys.exit(1)
```

## Best Practices

### Security

1. **Never commit secrets** to version control
2. **Use environment variables** for sensitive data
3. **Rotate secrets regularly** in production
4. **Use strong passwords** and keys
5. **Limit file permissions** on key files

### Performance

1. **Tune database connection pools** based on load
2. **Configure Redis for persistence** in production
3. **Set appropriate rate limits** for your use case
4. **Monitor resource usage** and adjust accordingly

### Development

1. **Use different configurations** for each environment
2. **Validate configuration** at startup
3. **Provide clear error messages** for missing configuration
4. **Document all configuration options**

## Troubleshooting

### Common Configuration Issues

1. **Missing Environment Variables**: Check that all required variables are set
2. **Invalid Database URL**: Ensure the connection string format is correct
3. **Permission Denied**: Check file permissions for JWT keys
4. **Connection Timeouts**: Verify network connectivity and firewall settings

### Configuration Validation

```bash
# Validate configuration without starting the app
python -c "from src.core.config.settings import settings; print('Configuration valid')"
```

## Next Steps

- Review the [Application Architecture](architecture/application-architecture.md) for configuration usage
- Check the [Deployment Guide](deployment/production.md) for production configuration
- Explore the [API Documentation](development/api-docs.md) for endpoint configuration 