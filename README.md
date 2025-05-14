# FastAPI Cedrina

## Project Overview

**FastAPI Cedrina** is a proprietary, enterprise-grade FastAPI template designed for building high-performance REST APIs and real-time WebSocket applications. It provides a robust foundation for scalable, secure, and maintainable services, supporting features like internationalization (i18n), structured logging, dependency injection, and environment-specific configurations. The template leverages a domain-driven design (DDD) architecture, making it ideal for complex, high-demand applications across development, staging, production, and test environments.

### Key Features
- **REST APIs**: Versioned endpoints (`/api/v1`) for core operations (e.g., health checks).
- **Real-Time Communication**: WebSocket support (`/ws`) for live updates.
- **Internationalization (i18n)**: Supports English (`en`), Persian (`fa`), and Arabic (`ar`) translations.
- **Modular Architecture**: DDD-inspired structure with adapters, domain, and infrastructure layers.
- **Observability**: Structured JSON logging with `structlog` for monitoring.
- **Security**: CORS, JWT-ready authentication, and secret key validation (minimum 32 characters).
- **Environment Management**: Configurations for `development`, `staging`, `production`, and `test`.
- **Dockerized Deployment**: Live reloading in development, optimized multi-stage builds for production.
- **CI/CD Readiness**: Testing, linting, and pre-commit hooks for code quality.

## Installation

### Prerequisites
- **Python 3.12.7**: Verify with `python --version`.
- **Poetry 1.8.3**: Install with `pip install poetry`.
- **Docker**: Latest Docker Desktop or CLI.
- **Git**: Latest version (verify with `git --version`).
- **Editor**: VS Code for live code changes.

### Steps
1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd fastapi-Cedrina
   ```

2. **Install Dependencies**:
   ```bash
   poetry install
   ```

3. **Set Up Environment**:
   - For local development, copy `.env.development` to `.env`:
     ```bash
     cp .env.development .env
     ```
   - Update `.env` with a unique `SECRET_KEY` (at least 32 characters, e.g., generated with `openssl rand -base64 32`).
   - Other environments (`staging`, `production`, `test`) use `.env.<env>` files included in the repository.

4. **Compile Translations**:
   ```bash
   make compile-translations
   ```

5. **Install Pre-Commit Hooks**:
   ```bash
   poetry run pre-commit install
   ```

## Running the Application

### Local Development (Without Docker)
1. Activate the Poetry environment:
   ```bash
   poetry shell
   ```
2. Ensure `.env` is set up with a valid `SECRET_KEY`.
3. Run the application:
   ```bash
   make run-local
   ```
   - This sets `PYTHONPATH` automatically.
5. Access:
   - REST: `http://localhost:8000/api/v1/health` (returns `{"status":"ok","env":"development","message":"System is operational"}` in English)
   - With language: `http://localhost:8000/api/v1/health?lang=fa` (returns Persian message)
   - WebSocket: `ws://localhost:8000/ws/health?lang=ar` (returns Arabic message)
   - Docs (if `DEBUG=true`): `http://localhost:8000/docs`

### Development with Docker
1. Ensure `.env` is set up.
2. Run Docker Compose:
   ```bash
   make run-dev
   ```
   - Mounts `src/` and `locales/` for live reloading.
   - Edit code in `src/` or `locales/`, and recompile translations if needed (`make compile-translations`).
3. Access the same endpoints as above.

### Staging
1. Build the Docker image:
   ```bash
   make build
   ```
2. Run the container:
   ```bash
   make run-staging
   ```
3. Access at `https://staging.example.com/api/v1/health` (configure DNS/load balancer).

### Production
1. Build the Docker image:
   ```bash
   make build
   ```
2. Run the container:
   ```bash
   make run-prod
   ```
3. Access at `https://example.com/api/v1/health` (configure DNS/load balancer).

## Testing
Unit and integration tests ensure reliability, including i18n functionality.

### Running Tests
1. Ensure `.env.test` exists with a valid `SECRET_KEY` (included in the repository).
2. Run tests with coverage:
   ```bash
   make test
   ```
   - Uses `.env.test` for the test environment.
   - Tests translations for English, Persian, and Arabic.
   - View coverage report in `htmlcov/index.html`.
3. Tests are in:
   - `tests/unit/`: Unit tests (e.g., `test_health.py`).
   - `tests/integration/`: Integration tests (to be added).

### Test Configuration
- `pytest.ini` sets `pythonpath = src` for module resolution and loads `.env.test` via `pytest-dotenv`.
- Async tests are supported with `pytest-asyncio`.

### Troubleshooting Tests
- **ModuleNotFoundError**: Verify `pytest.ini` exists and `pythonpath = src` is set.
- **Validation Errors**: Ensure `.env.test` has a `SECRET_KEY` with at least 32 characters.
- **Translation Errors**:
  - Verify `messages.mo` files exist in `locales/<lang>/LC_MESSAGES/`.
  - Run `make compile-translations` after editing `.po` files.
  - Check logs for `i18n_initialized` and `translation_fetched` messages.
- **Cache Issues**: Clear pytest cache:
  ```bash
  rm -rf .pytest_cache
  ```

## Internationalization (i18n)
- **Supported Languages**: English (`en`), Persian (`fa`), Arabic (`ar`).
- **Translation Files**: Located in `locales/<lang>/LC_MESSAGES/messages.po`.
- **Usage**:
  - API: Set `Accept-Language` header (e.g., `Accept-Language: fa`) or query parameter (`lang=fa`).
  - WebSocket: Use query parameter (`lang=ar`).
  - Example: `curl -H "Accept-Language: ar" http://localhost:8000/api/v1/health`
- **Updating Translations**:
  - Extract new keys:
    ```bash
    make update-translations
    ```
  - Edit `locales/<lang>/LC_MESSAGES/messages.po`.
  - Compile:
    ```bash
    make compile-translations
    ```

## Code Quality
- **Linting**:
  ```bash
  make lint
  ```
  - Uses `ruff` and `mypy`.
- **Formatting**:
  ```bash
  make format
  ```
  - Uses `black` and `ruff`.
- **Pre-Commit Hooks**: Enforce quality on `git commit`.

## Building and Releasing

### Building
1. Update `pyproject.toml` version (e.g., `version = "0.2.0"`).
2. Compile translations:
   ```bash
   make compile-translations
   ```
3. Build the Docker image:
   ```bash
   make build
   ```
4. Tag the image:
   ```bash
   docker tag fastapi-Cedrina:latest <registry>/fastapi-Cedrina:0.2.0
   ```

### Releasing
1. Push to the registry:
   ```bash
   docker push <registry>/fastapi-Cedrina:0.2.0
   ```
2. Deploy:
   - Pull the image:
     ```bash
     docker pull <registry>/fastapi-Cedrina:0.2.0
     ```
   - Run:
     ```bash
     make run-staging  # or make run-prod
     ```

### Rollback
- Redeploy a previous image:
  ```bash
  docker run -d -p 8000:8000 --env-file .env.production <registry>/fastapi-Cedrina:0.1.0
  ```

## Directory Structure
- **src/**: Application code
  - **adapters/**: REST (`api/v1`) and WebSockets (`websockets`).
  - **core/**: `config`, `logging`, `dependencies`.
  - **domain/**: `entities`, `services` (DDD).
  - **infrastructure/**: `database`, future brokers.
  - **utils/**: Helpers, including `i18n.py`.
- **locales/**: Translation files (`en`, `fa`, `ar`).
- **tests/**: `unit`, `integration`.
- **scripts/**: Utility scripts.
- **docs/**: Documentation.
- **.env.<env>**: `development`, `staging`, `production`, `test`.

## Environment Configuration
- **.env.development**: Local development, copy to `.env`.
- **.env.staging**: Staging, used in Docker.
- **.env.production**: Production, used in Docker.
- **.env.test**: Testing, used by `pytest`.
- Update `SECRET_KEY` (minimum 32 characters) and `ALLOWED_ORIGINS` in each file.
- Example `SECRET_KEY` generation:
  ```bash
  openssl rand -base64 32
  ```

## Troubleshooting
- **ValidationError (SECRET_KEY)**:
  - Ensure `SECRET_KEY` in `.env` or `.env.<env>` is at least 32 characters.
- **ModuleNotFoundError**:
  - Use `make run-local` or `make test` to set `PYTHONPATH`.
  - In Docker, `PYTHONPATH=/app` is set automatically.
- **Translation Issues**:
  - Verify `messages.mo` files in `locales/<lang>/LC_MESSAGES/`.
  - Run `make compile-translations` after editing `.po` files.
  - Check logs for `i18n_initialized` and `translation_fetched` entries.
- **Docker Issues**: Ensure ports are free (`docker ps`).
- **Logs**: Check JSON logs (`docker logs <container>`).

## Development Workflow
1. Run `make run-dev` or `make run-local`.
2. Edit `src/` or `locales/`; recompile translations if needed (`make compile-translations`).
3. Run `make test` frequently.
4. Commit with Git, ensuring pre-commit hooks pass.
5. Push to the repository.

## Deployment Notes
- **Staging**: Use load balancer, monitor logs.
- **Production**: Implement auto-scaling, health checks.
- **Secrets**: Use a vault for `SECRET_KEY`.

## Customization
To adapt **FastAPI Cedrina** for your project:
- **Rename the Project**:
  - Update `name` in `pyproject.toml`.
  - Replace `fastapi-Cedrina` in `Dockerfile`, `docker-compose.yml`, and build commands.
- **Add Endpoints**: Extend `src/adapters/api/v1/` with new routes.
- **Expand i18n**: Add languages by creating new `locales/<lang>/LC_MESSAGES/messages.po` files and updating `SUPPORTED_LANGUAGES` in `settings.py`.
- **Integrate Database**: Add ORM (e.g., SQLAlchemy) in `src/infrastructure/database/`.
- **Add Authentication**: Implement JWT in `src/core/dependencies/`.

## Future Enhancements
- Database integration (SQLAlchemy, Tortoise ORM).
- JWT authentication.
- Message broker (Redis, RabbitMQ).
- Monitoring (Prometheus, Grafana).
- Additional languages for i18n.

---

This document is for internal team use only. Contact the architecture team for support.