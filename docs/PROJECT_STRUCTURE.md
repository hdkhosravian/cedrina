# Cedrina Project Structure

## Overview
The **Cedrina** project is organized using a `src/` layout, with a clear separation of concerns between application code, configuration, migrations, translations, tests, and documentation. The structure follows domain-driven design (DDD) principles, modularizing code into layers (adapters, core, domain, infrastructure, utils) to enhance maintainability and scalability. Below is a detailed breakdown of the directories and files.

## Root Directory
The project root contains configuration files, Docker-related files, and top-level directories for code, tests, and resources.

- **.env**: Default environment file for development, copied from `.env.development`. Contains project metadata, API settings, logging, security, database, Redis, and Docker configurations.
- **.env.development**: Environment file for local development with debug settings, local PostgreSQL/Redis, and default credentials.
- **.env.test**: Environment file for testing with isolated database settings and local instance defaults.
- **.env.staging**: Environment file for staging with external PostgreSQL/Redis server settings and SSL enabled.
- **.env.production**: Environment file for production with external PostgreSQL/Redis server settings, SSL, and optimized worker settings.
- **Dockerfile**: Multi-stage Docker configuration for building, precompiling, and running the application. Defines `builder`, `precompiler`, and `runtime` stages.
- **docker-compose.yml**: Docker Compose configuration for development and testing, defining `api`, `postgres`, and `redis` services with conditional profiles and persistent volumes.
- **entrypoint.sh**: Shell script executed as the Docker container’s entrypoint, handling startup tasks (e.g., migrations, server start).
- **pyproject.toml**: Poetry configuration file defining project metadata, dependencies (e.g., FastAPI, SQLModel, Redis), development dependencies, and tool settings (mypy, ruff, black).
- **poetry.lock**: Lock file ensuring reproducible dependency installations.
- **Makefile**: Defines build, run, test, lint, format, translation, and migration tasks for local and Docker workflows.
- **README.md**: Project documentation with setup instructions, usage, and troubleshooting (not detailed here).
- **babel.cfg**: Configuration for Babel to extract translation keys from source code.
- **pytest.ini**: Pytest configuration, setting `pythonpath = src` and loading `.env.test` via `pytest-dotenv`.

### Directories
- **alembic/**: Database migration scripts and configuration.
- **docs/**: Documentation resources (e.g., architecture diagrams, API specs).
- **locales/**: Translation files for internationalization (i18n).
- **scripts/**: Utility scripts for automation or maintenance tasks.
- **src/**: Application source code, following DDD structure.
- **tests/**: Unit and integration tests.

## Directory Breakdown

### alembic/
Contains Alembic configuration and migration scripts for managing PostgreSQL database schema changes.

- **env.py**: Alembic environment script, configuring the migration context, connecting to the database using `settings.DATABASE_URL`, and defining `target_metadata` for SQLModel.
- **script.py.mako**: Template for generating migration scripts, defining revision metadata and `upgrade`/`downgrade` functions.
- **versions/**: Directory for auto-generated migration scripts (e.g., `<revision_id>_<message>.py`), each containing database schema changes.

### docs/
Stores documentation files, such as Markdown guides, architecture diagrams, or API specifications. Currently empty or placeholder, intended for project-specific documentation.

### locales/
Holds translation files for i18n, supporting English (`en`), Persian (`fa`), and Arabic (`ar`).

- **en/**:
  - **LC_MESSAGES/**:
    - **messages.po**: English translation source file with `msgid` and `msgstr` pairs.
    - **messages.mo**: Compiled binary translation file for English.
- **fa/**:
  - **LC_MESSAGES/**:
    - **messages.po**: Persian translation source file.
    - **messages.mo**: Compiled binary translation file for Persian.
- **ar/**:
  - **LC_MESSAGES/**:
    - **messages.po**: Arabic translation source file.
    - **messages.mo**: Compiled binary translation file for Arabic.
- **messages.pot**: Template file for translation keys extracted from source code.

### scripts/
Contains utility scripts for tasks like data seeding, maintenance, or custom CLI commands. Currently empty or placeholder, intended for project-specific scripts.

### src/
The core application code, organized into DDD-inspired layers: adapters, core, domain, infrastructure, and utils.

- **adapters/**: Interfaces between the application and external systems (e.g., HTTP, WebSockets).
  - **api/**:
    - **v1/**: Versioned REST API endpoints.
      - **__init__.py**: Exposes API router for version 1.
      - **health.py**: Defines health check endpoint (`/api/v1/health`).
      - **routes.py**: Aggregates API routes for version 1.
  - **websockets/**:
    - **__init__.py**: Exposes WebSocket router.
    - **health.py**: Defines WebSocket health check endpoint (`/ws/health`).
- **core/**: Application configuration, logging, and dependencies.
  - **config/**:
    - **__init__.py**: Exposes configuration settings.
    - **settings.py**: Defines `Settings` class with Pydantic for environment variable validation (e.g., database, Redis, API settings).
  - **logging/**:
    - **__init__.py**: Exposes logging configuration.
    - **logger.py**: Configures `structlog` for structured JSON logging.
  - **dependencies/**:
    - **__init__.py**: Exposes dependency injection utilities.
    - **auth.py**: Placeholder for JWT authentication dependencies (not implemented).
- **domain/**: Business logic and entities.
  - **entities/**:
    - **__init__.py**: Exposes domain entities.
    - (Placeholder for SQLModel models, e.g., `user.py` for User entity, not yet implemented.)
  - **services/**:
    - **__init__.py**: Exposes domain services.
    - (Placeholder for business logic services, not yet implemented.)
- **infrastructure/**: External system implementations (e.g., database, message brokers).
  - **database/**:
    - **__init__.py**: Exposes database functions (`create_db_and_tables`, `check_database_health`, `get_db`).
    - **database.py**: Configures SQLModel engine, defines health check, table creation, and session management.
  - (Placeholder for future brokers, e.g., `redis.py` for Redis client.)
- **utils/**: Helper functions and cross-cutting concerns.
  - **__init__.py**: Exposes utility functions.
  - **i18n.py**: Configures i18n with `python-i18n`, handling translation loading and language selection.
- **main.py**: Application entry point, defining FastAPI app, middleware (CORS, language), routers, and startup/shutdown events.

### tests/
Contains unit and integration tests, mirroring the `src/` structure.

- **unit/**: Unit tests for individual components.
  - **__init__.py**: Empty, marks directory as a package.
  - **test_database.py**: Tests for `src/infrastructure/database/database.py` (e.g., health check, session management).
  - (Placeholder for additional unit tests, e.g., `test_i18n.py`.)
- **integration/**: Integration tests for API and WebSocket endpoints.
  - **__init__.py**: Empty, marks directory as a package.
  - (Placeholder for integration tests, not yet implemented.)

## File and Folder Summary
- **Root Files**: Configuration (`pyproject.toml`, `poetry.lock`, `.env*`), Docker (`Dockerfile`, `docker-compose.yml`, `entrypoint.sh`), and build tools (`Makefile`, `babel.cfg`, `pytest.ini`).
- **alembic/**: Manages database migrations with configuration (`env.py`, `script.py.mako`) and version scripts (`versions/`).
- **docs/**: Placeholder for documentation.
- **locales/**: Translation files for i18n (`en`, `fa`, `ar` with `.po` and `.mo` files).
- **scripts/**: Placeholder for utility scripts.
- **src/**: DDD-structured application code:
  - `adapters/`: REST (`api/v1`) and WebSocket (`websockets`) interfaces.
  - `core/`: Configuration (`settings`), logging, and dependencies.
  - `domain/`: Business entities and services (placeholder).
  - `infrastructure/`: Database (`database.py`) and future brokers.
  - `utils/`: i18n and helpers.
  - `main.py`: FastAPI application entry point.
- **tests/**: Unit (`unit/`) and integration (`integration/`) tests, mirroring `src/`.

## Structure Design
- **DDD Alignment**: Separates concerns into adapters (external interfaces), core (configuration), domain (business logic), infrastructure (external systems), and utils (cross-cutting).
- **Src Layout**: Uses `src/` to isolate application code, improving modularity and testing.
- **Modularity**: Each directory (`adapters`, `core`, etc.) is a package with `__init__.py`, enabling clear imports and extensibility.
- **Scalability**: Supports additional features (e.g., new entities, brokers) by extending `domain/` and `infrastructure/`.
- **Maintainability**: Consistent file naming, clear separation of concerns, and configuration isolation enhance code maintenance.

This structure ensures the **Cedrina** project is organized for scalability, maintainability, and alignment with modern Python and DDD best practices.