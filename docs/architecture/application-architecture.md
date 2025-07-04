# Application Architecture

## Overview

Cedrina implements **Clean Architecture** principles with **Domain-Driven Design (DDD)** to create a maintainable, testable, and scalable application. The architecture separates concerns into distinct layers, ensuring that business logic is independent of external frameworks and infrastructure.

## Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Adapters Layer                           │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │   REST API      │  │   WebSockets    │  │   External   │ │
│  │   Endpoints     │  │   Endpoints     │  │   Services   │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     Core Layer                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │   Application   │  │   Middleware    │  │   Exception  │ │
│  │    Factory      │  │  Configuration  │  │   Handlers   │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │   Lifecycle     │  │   Dependency    │  │   Rate       │ │
│  │  Management     │  │   Injection     │  │  Limiting    │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Domain Layer                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │    Entities     │  │   Value Objects │  │   Services   │ │
│  │                 │  │                 │  │              │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │     Events      │  │   Interfaces    │  │  Validation  │ │
│  │                 │  │                 │  │              │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                Infrastructure Layer                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │    Database     │  │  Repositories   │  │   External   │ │
│  │  Connections    │  │                 │  │   Services   │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Layer Responsibilities

### 1. Adapters Layer (`src/adapters/`)

**Purpose**: Handles external communication and adapts external requests to internal domain operations.

**Components**:
- **REST API Adapters** (`api/`): HTTP endpoints using FastAPI
- **WebSocket Adapters** (`websockets/`): Real-time communication
- **External Service Adapters**: Integration with third-party services

**Key Principles**:
- Thin layer that only handles HTTP/WebSocket concerns
- No business logic
- Converts external formats to domain objects
- Handles authentication and authorization at the boundary

**Example**:
```python
@router.post("/auth/login")
async def login(
    credentials: LoginRequest,
    auth_service: UserAuthenticationService = Depends(get_auth_service)
) -> LoginResponse:
    """Handle login requests."""
    user = await auth_service.authenticate_user(credentials.username, credentials.password)
    return LoginResponse.from_user(user)
```

### 2. Core Layer (`src/core/`)

**Purpose**: Application configuration, lifecycle management, and cross-cutting concerns.

**Components**:

#### Application Factory (`application.py`)
```python
def create_application() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        lifespan=create_lifespan_manager(),
        # ... other configuration
    )
    
    configure_middleware(app)
    register_exception_handlers(app)
    include_routers(app)
    
    return app
```

#### Lifecycle Management (`lifecycle.py`)
```python
def create_lifespan_manager():
    """Create the application lifespan manager."""
    
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup: Database health check, table creation, limiter setup
        if not check_database_health():
            raise RuntimeError("Database unavailable")
        create_db_and_tables()
        app.state.limiter = get_limiter()
        
        yield
        
        # Shutdown: Cleanup resources
        logger.info("application_shutdown")
    
    return lifespan
```

#### Middleware Configuration (`middleware.py`)
```python
def configure_middleware(app: FastAPI) -> None:
    """Configure all middleware for the FastAPI application."""
    # CORS middleware
    app.add_middleware(CORSMiddleware, ...)
    
    # Rate limiting middleware
    app.add_middleware(SlowAPIMiddleware)
    
    # Language middleware
    app.middleware("http")(set_language_middleware)
```

#### Initialization (`initialization.py`)
```python
def initialize_application() -> None:
    """Initialize the application with all necessary setup tasks."""
    load_dotenv(override=True)
    configure_logging(log_level=settings.LOG_LEVEL, json_logs=settings.LOG_JSON)
    setup_i18n()
```

### 3. Domain Layer (`src/domain/`)

**Purpose**: Contains business logic, entities, and domain rules. This is the heart of the application.

**Components**:

#### Entities (`entities/`)
Domain objects with identity and lifecycle:
```python
class User(SQLModel, table=True):
    """User domain entity."""
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
```

#### Value Objects (`value_objects/`)
Immutable objects without identity:
```python
class Password:
    """Password value object with validation."""
    def __init__(self, value: str):
        self._validate_password(value)
        self._value = value
    
    @staticmethod
    def _validate_password(password: str) -> None:
        if len(password) < 8:
            raise PasswordValidationError("Password too short")
        # ... other validation rules
```

#### Domain Services (`services/`)
Business logic that doesn't belong to a single entity:
```python
class UserAuthenticationService:
    """Domain service for user authentication."""
    
    def __init__(self, user_repository: UserRepository, password_service: PasswordService):
        self.user_repository = user_repository
        self.password_service = password_service
    
    async def authenticate_user(self, username: str, password: str) -> User:
        """Authenticate a user with username and password."""
        user = await self.user_repository.find_by_username(username)
        if not user or not self.password_service.verify_password(password, user.hashed_password):
            raise AuthenticationError("Invalid credentials")
        return user
```

#### Domain Events (`events/`)
Events that occur within the domain:
```python
class UserRegisteredEvent(DomainEvent):
    """Event raised when a user is registered."""
    user_id: int
    username: str
    email: str
    timestamp: datetime
```

### 4. Infrastructure Layer (`src/infrastructure/`)

**Purpose**: Implements external system integrations and technical concerns.

**Components**:

#### Database (`database/`)
Database connection and session management:
```python
def get_db() -> Generator[Session, None, None]:
    """Database session dependency."""
    with get_db_session() as session:
        yield session

def check_database_health() -> bool:
    """Check database connectivity."""
    try:
        with get_db_session() as session:
            session.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
```

#### Repositories (`repositories/`)
Data access implementations:
```python
class UserRepository:
    """User repository implementation."""
    
    def __init__(self, db_session: Session):
        self.db_session = db_session
    
    async def find_by_username(self, username: str) -> Optional[User]:
        """Find user by username."""
        return self.db_session.query(User).filter(User.username == username).first()
```

## Dependency Flow

The architecture follows the **Dependency Rule**: dependencies point inward, with the domain layer at the center.

```
Adapters → Core → Domain ← Infrastructure
```

- **Adapters** depend on **Core** and **Domain**
- **Core** depends on **Domain**
- **Infrastructure** depends on **Domain**
- **Domain** has no dependencies on other layers

## Application Entry Point

The main entry point (`src/main.py`) is now clean and minimal:

```python
"""Main application entry point for the FastAPI application."""

from src.core.application import create_application
from src.core.initialization import initialize_application

# Initialize the application
initialize_application()

# Create the FastAPI application
app = create_application()
```

## Configuration Management

Configuration is centralized and environment-based:

```python
# src/core/config/settings.py
class Settings(AppSettings, DatabaseSettings, RedisSettings, AuthSettings, EmailSettings):
    """Main settings class that aggregates all configurations."""
    
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8", 
        case_sensitive=True, 
        extra="allow"
    )
```

## Benefits of This Architecture

### 1. **Testability**
- Domain logic can be tested without external dependencies
- Each layer can be tested in isolation
- Easy to mock dependencies for unit tests

### 2. **Maintainability**
- Clear separation of concerns
- Changes in one layer don't affect others
- Easy to understand and modify

### 3. **Scalability**
- Easy to add new features without affecting existing code
- Can scale different layers independently
- Supports microservices evolution

### 4. **Technology Independence**
- Domain logic is independent of frameworks
- Easy to change database, web framework, or external services
- Business rules are preserved regardless of technical changes

### 5. **Team Collaboration**
- Different teams can work on different layers
- Clear interfaces between layers
- Reduced merge conflicts

## Design Patterns Used

### 1. **Factory Pattern**
- Application factory for creating and configuring the FastAPI app
- Repository factory for data access

### 2. **Dependency Injection**
- FastAPI's dependency injection system
- Clean separation of concerns

### 3. **Repository Pattern**
- Abstract data access through interfaces
- Domain doesn't know about database implementation

### 4. **Event-Driven Architecture**
- Domain events for loose coupling
- Event handlers for side effects

### 5. **Value Objects**
- Immutable objects for domain concepts
- Validation and business rules encapsulation

This architecture ensures that Cedrina is built on solid foundations that support long-term maintainability, scalability, and alignment with modern software engineering best practices. 