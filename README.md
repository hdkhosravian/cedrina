# Cedrina

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Cedrina** is a production-ready FastAPI template built with clean architecture principles and domain-driven design. It provides a robust foundation for building scalable, secure, and maintainable REST APIs and WebSocket applications.

## ✨ Features

- 🏗️ **Clean Architecture** with Domain-Driven Design (DDD)
- 🔐 **Enterprise Authentication** with JWT, OAuth 2.0, and session management
- 🚀 **High Performance** with async/await and connection pooling
- 🌍 **Internationalization** (i18n) with multi-language support
- 🛡️ **Security First** with rate limiting, input validation, and audit logging
- 📊 **Observability** with structured logging and metrics
- 🐳 **Docker Ready** with multi-stage builds and production optimization
- 🧪 **Comprehensive Testing** with 95%+ coverage
- 📚 **Complete Documentation** with guides and examples

## 🚀 Quick Start

   ```bash
# Clone the repository
git clone https://github.com/hdkhosravian/cedrina.git
   cd cedrina

# Install dependencies
   poetry install

# Start the application
     make run-dev

# Verify it's working
curl http://localhost:8000/api/v1/health
```

For detailed setup instructions, see the **[Quick Start Guide](docs/getting-started/quick-start.md)**.

## 📚 Documentation

Comprehensive documentation is available in the [`docs/`](docs/) directory:

### Getting Started
- **[Quick Start Guide](docs/getting-started/quick-start.md)** - Get up and running in minutes
- **[Installation](docs/getting-started/installation.md)** - Detailed installation instructions
- **[Configuration](docs/getting-started/configuration.md)** - Environment and application configuration

### Architecture
- **[Project Structure](docs/architecture/project-structure.md)** - Code organization and DDD principles
- **[Application Architecture](docs/architecture/application-architecture.md)** - Clean architecture implementation
- **[Database Design](docs/architecture/database-design.md)** - Database schema and relationships

### Core Features
- **[Authentication System](docs/features/authentication/README.md)** - Complete authentication documentation
- **[Rate Limiting](docs/features/rate-limiting/README.md)** - Advanced rate limiting system
- **[Permissions & Authorization](docs/features/permissions/README.md)** - Role-based access control
- **[Internationalization (i18n)](docs/features/internationalization.md)** - Multi-language support

### Development
- **[Development Setup](docs/development/setup.md)** - Local development environment
- **[Testing Guide](docs/development/testing.md)** - Comprehensive testing strategy
- **[Code Quality](docs/development/code-quality.md)** - Linting, formatting, and best practices
- **[API Documentation](docs/development/api-docs.md)** - API endpoints and usage

### Deployment
- **[Docker Deployment](docs/deployment/docker.md)** - Containerized deployment
- **[Production Setup](docs/deployment/production.md)** - Production environment configuration
- **[Environment Management](docs/deployment/environments.md)** - Development, staging, and production

## 🏗️ Architecture

Cedrina follows clean architecture principles with clear separation of concerns:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Adapters      │    │      Core       │    │    Domain       │
│                 │    │                 │    │                 │
│ • REST API      │◄──►│ • Application   │◄──►│ • Entities      │
│ • WebSockets    │    │ • Middleware    │    │ • Services      │
│ • External      │    │ • Lifecycle     │    │ • Value Objects │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │ Infrastructure  │
                       │                 │
                       │ • Database      │
                       │ • Repositories  │
                       │ • External      │
                       └─────────────────┘
```

## 🔧 Core Components

### Authentication System
- **Username/Password**: Secure authentication with bcrypt hashing
- **OAuth 2.0**: Google, Microsoft, and Facebook integration
- **JWT Tokens**: RS256-signed access and refresh tokens
- **Session Management**: Secure session tracking and revocation
- **Rate Limiting**: Protection against brute force attacks

### Database & Caching
- **PostgreSQL 16**: Primary database with connection pooling
- **Redis 7.2**: Caching and session storage
- **Alembic**: Database migrations
- **SQLModel**: Type-safe ORM with Pydantic integration

### Security Features
- **Input Validation**: Comprehensive Pydantic validation
- **Rate Limiting**: Redis-based rate limiting with multiple strategies
- **CORS**: Configurable cross-origin resource sharing
- **Audit Logging**: Structured logging for security events
- **Password Policies**: Enforced password complexity requirements

## 🛠️ Development

### Prerequisites
- Python 3.12+
- Poetry
- Docker
- PostgreSQL 16
- Redis 7.2

### Commands

     ```bash
# Development
make run-dev              # Start with Docker
make run-dev-local        # Start locally
make test                 # Run tests
make test-cov            # Run tests with coverage

# Code Quality
make format              # Format code
make lint                # Lint code
make type-check          # Type checking

# Database
make db-migrate          # Apply migrations
make db-rollback         # Rollback migrations

# Translations
make compile-translations # Compile i18n files
```

## 🚀 Deployment

### Docker Deployment
     ```bash
# Build production image
     make build-prod

# Run in production
     make run-prod
     ```

### Environment Configuration
- **Development**: `.env.development`
- **Staging**: `.env.staging`
- **Production**: `.env.production`

## 🧪 Testing

Cedrina includes comprehensive testing with 95%+ coverage:

- **Unit Tests**: Individual component testing
- **Integration Tests**: API endpoint testing
- **Feature Tests**: End-to-end workflow testing
- **Performance Tests**: Load and stress testing

   ```bash
# Run all tests
make test

# Run specific test categories
poetry run pytest tests/unit/ -v
poetry run pytest tests/integration/ -v
poetry run pytest tests/feature/ -v
```

## 📊 Performance

- **Async/Await**: Non-blocking I/O operations
- **Connection Pooling**: Optimized database connections
- **Caching**: Redis-based caching strategies
- **Rate Limiting**: Multiple algorithms (fixed-window, sliding-window, token-bucket)

## 🔗 API Endpoints

### Authentication
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/oauth` - OAuth authentication
- `DELETE /api/v1/auth/logout` - User logout
- `PUT /api/v1/auth/change-password` - Password change

### System
- `GET /api/v1/health` - Health check
- `GET /api/v1/metrics` - Application metrics
- `WS /ws/health` - WebSocket health check

## 🌍 Internationalization

Supports multiple languages:
- **English** (`en`)
- **Spanish** (`es`)
- **Persian** (`fa`)
- **Arabic** (`ar`)

Usage:
    ```bash
# API with language header
curl -H "Accept-Language: fa" http://localhost:8000/api/v1/health

# API with query parameter
curl http://localhost:8000/api/v1/health?lang=ar
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow the established architecture patterns
- Add comprehensive tests for new features
- Update documentation for changes
- Ensure code quality with linting and formatting
- Follow the testing strategy

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check the [documentation](docs/)
- **Issues**: Create an issue on [GitHub](https://github.com/hdkhosravian/cedrina/issues)
- **Discussions**: Join the [GitHub Discussions](https://github.com/hdkhosravian/cedrina/discussions)

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - Modern, fast web framework
- [SQLModel](https://sqlmodel.tiangolo.com/) - SQL databases in Python, designed for simplicity and compatibility
- [Pydantic](https://pydantic-docs.helpmanual.io/) - Data validation using Python type annotations
- [Alembic](https://alembic.sqlalchemy.org/) - Database migration tool
- [Redis](https://redis.io/) - In-memory data structure store

---

**Built with ❤️ using clean architecture and domain-driven design principles.**