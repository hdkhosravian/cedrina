# Project Structure

## Overview

Cedrina follows a **Domain-Driven Design (DDD)** architecture with a clean, modular structure that separates concerns and promotes maintainability. The project uses a `src/` layout for better code organization and testing isolation.

## Directory Structure

```
cedrina/
├── src/                          # Application source code
│   ├── adapters/                 # External interfaces layer
│   │   ├── api/                  # REST API endpoints
│   │   │   └── v1/              # API version 1
│   │   │       ├── auth/        # Authentication endpoints
│   │   │       ├── admin/       # Admin endpoints
│   │   │       ├── health.py    # Health check endpoint
│   │   │       └── docs.py      # API documentation
│   │   └── websockets/          # WebSocket endpoints
│   ├── core/                     # Application core layer
│   │   ├── application.py       # Application factory
│   │   ├── lifecycle.py         # Application lifecycle management
│   │   ├── middleware.py        # Middleware configuration
│   │   ├── initialization.py    # Application initialization
│   │   ├── config/              # Configuration management
│   │   ├── dependencies/        # Dependency injection
│   │   ├── exceptions.py        # Custom exceptions
│   │   ├── handlers.py          # Exception handlers
│   │   ├── logging/             # Logging configuration
│   │   ├── rate_limiting/       # Rate limiting system
│   │   └── metrics.py           # Application metrics
│   ├── domain/                   # Domain layer (DDD)
│   │   ├── entities/            # Domain entities
│   │   ├── value_objects/       # Value objects
│   │   ├── services/            # Domain services
│   │   ├── events/              # Domain events
│   │   ├── interfaces/          # Repository interfaces
│   │   ├── validation/          # Input validation
│   │   └── security/            # Security utilities
│   ├── infrastructure/           # Infrastructure layer
│   │   ├── database/            # Database implementations
│   │   ├── repositories/        # Repository implementations
│   │   ├── services/            # External service adapters
│   │   ├── dependency_injection/ # DI configuration
│   │   └── redis.py             # Redis client
│   ├── permissions/              # Authorization system
│   ├── utils/                    # Utility functions
│   └── main.py                   # Application entry point
├── tests/                        # Test suite
│   ├── unit/                     # Unit tests
│   ├── integration/              # Integration tests
│   ├── feature/                  # Feature tests
│   └── conftest.py               # Test configuration
├── docs/                         # Documentation
├── alembic/                      # Database migrations
├── locales/                      # Internationalization files
├── scripts/                      # Utility scripts
└── configuration files           # Various config files
```

## Architecture Layers

### 1. Adapters Layer (`src/adapters/`)

**Purpose**: Handles external communication and interfaces.

**Components**:
- **API Adapters** (`api/`): REST API endpoints using FastAPI
- **WebSocket Adapters** (`websockets/`): Real-time communication endpoints

**Key Files**:
- `src/adapters/api/v1/health.py` - Health check endpoint
- `src/adapters/api/v1/auth/routes/` - Authentication endpoints
- `src/adapters/websockets/` - WebSocket endpoints

### 2. Core Layer (`src/core/`)

**Purpose**: Application configuration, lifecycle, and cross-cutting concerns.

**Components**:
- **Application Factory** (`application.py`): Creates and configures the FastAPI app
- **Lifecycle Management** (`lifecycle.py`): Startup/shutdown events
- **Middleware Configuration** (`middleware.py`): CORS, rate limiting, language
- **Initialization** (`initialization.py`): Environment setup, logging, i18n
- **Configuration** (`config/`): Environment-based settings
- **Dependencies** (`dependencies/`): FastAPI dependency injection
- **Exception Handling** (`handlers.py`): Global exception handlers
- **Rate Limiting** (`rate_limiting/`): Advanced rate limiting system

**Key Files**:
- `src/core/application.py` - Application factory pattern
- `src/core/lifecycle.py` - Application lifecycle management
- `src/core/middleware.py` - Middleware configuration
- `src/core/initialization.py` - Application initialization

### 3. Domain Layer (`src/domain/`)

**Purpose**: Business logic, entities, and domain rules (DDD core).

**Components**:
- **Entities** (`entities/`): Domain objects with identity
- **Value Objects** (`value_objects/`): Immutable domain values
- **Services** (`services/`): Domain business logic
- **Events** (`events/`): Domain events for event-driven architecture
- **Interfaces** (`interfaces/`): Repository and service contracts
- **Validation** (`validation/`): Input validation and sanitization
- **Security** (`security/`): Security utilities and patterns

**Key Files**:
- `src/domain/entities/user.py` - User domain entity
- `src/domain/entities/session.py` - Session domain entity
- `src/domain/services/authentication/` - Authentication domain services
- `src/domain/value_objects/` - Domain value objects

### 4. Infrastructure Layer (`src/infrastructure/`)

**Purpose**: External system implementations and technical concerns.

**Components**:
- **Database** (`database/`): Database connections and operations
- **Repositories** (`repositories/`): Data access implementations
- **Services** (`services/`): External service integrations
- **Dependency Injection** (`dependency_injection/`): DI configuration

**Key Files**:
- `src/infrastructure/database/database.py` - Database connection management
- `src/infrastructure/repositories/user_repository.py` - User data access
- `src/infrastructure/services/` - External service adapters

### 5. Permissions (`src/permissions/`)

**Purpose**: Role-based access control and authorization.

**Components**:
- **Enforcer** (`enforcer.py`): Casbin-based policy enforcement
- **Dependencies** (`dependencies.py`): Authorization dependencies
- **Policies** (`policies.py`): Access control policies

### 6. Utils (`src/utils/`)

**Purpose**: Cross-cutting utility functions.

**Components**:
- **Internationalization** (`i18n.py`): Multi-language support
- **Security** (`security.py`): Security utilities

## Key Architectural Principles

### 1. Dependency Rule
Dependencies flow inward: Infrastructure → Domain ← Core ← Adapters

### 2. Single Responsibility Principle
Each module has a single, well-defined responsibility.

### 3. Clean Architecture
- **Independence of frameworks**: Core business logic is framework-agnostic
- **Testability**: Easy to unit test without external dependencies
- **Independence of UI**: Business logic is independent of presentation
- **Independence of Database**: Domain logic doesn't depend on database implementation

### 4. Domain-Driven Design
- **Ubiquitous Language**: Code and documentation use consistent domain terminology
- **Bounded Contexts**: Clear boundaries between different parts of the system
- **Aggregates**: Entities are grouped into aggregates with consistency boundaries

## File Naming Conventions

- **Modules**: Lowercase with underscores (`user_authentication.py`)
- **Classes**: PascalCase (`UserAuthenticationService`)
- **Functions**: Lowercase with underscores (`authenticate_user`)
- **Constants**: Uppercase with underscores (`MAX_LOGIN_ATTEMPTS`)
- **Files**: Descriptive names that indicate purpose

## Import Structure

```python
# External libraries first
from fastapi import FastAPI
from sqlmodel import Session

# Internal imports (relative to src/)
from src.core.config.settings import settings
from src.domain.entities.user import User
from src.infrastructure.repositories.user_repository import UserRepository
```

## Testing Structure

The test structure mirrors the source code structure:

```
tests/
├── unit/                    # Unit tests for individual components
│   ├── adapters/           # API and WebSocket tests
│   ├── core/               # Core functionality tests
│   ├── domain/             # Domain logic tests
│   └── infrastructure/     # Infrastructure tests
├── integration/            # Integration tests
├── feature/                # End-to-end feature tests
└── conftest.py            # Test configuration and fixtures
```

## Configuration Management

Configuration is centralized in `src/core/config/`:

- **Settings** (`settings.py`): Main settings class
- **App Settings** (`app.py`): Application-specific settings
- **Database Settings** (`database.py`): Database configuration
- **Auth Settings** (`auth.py`): Authentication configuration
- **Redis Settings** (`redis.py`): Redis configuration
- **Email Settings** (`email.py`): Email configuration

## Benefits of This Structure

1. **Maintainability**: Clear separation of concerns makes code easier to maintain
2. **Testability**: Each layer can be tested independently
3. **Scalability**: Easy to add new features without affecting existing code
4. **Team Collaboration**: Different teams can work on different layers
5. **Technology Independence**: Core business logic is independent of frameworks
6. **Domain Focus**: Business logic is clearly separated from technical concerns

This structure ensures that Cedrina is organized for long-term maintainability, scalability, and alignment with modern software engineering best practices. 