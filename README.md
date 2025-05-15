# Cedrina

## Project Overview

**Cedrina** is a proprietary, enterprise-grade FastAPI template designed for building high-performance REST APIs and real-time WebSocket applications. It provides a robust foundation for scalable, secure, and maintainable services, supporting features like internationalization (i18n), structured logging, dependency injection, PostgreSQL-backed data persistence, and Redis for caching or messaging. The template leverages a domain-driven design (DDD) architecture, making it ideal for complex, high-demand applications across development, staging, production, and test environments.

### Key Features
- **REST APIs**: Versioned endpoints (`/api/v1`) for core operations (e.g., health checks).
- **Real-Time Communication**: WebSocket support (`/ws`) for live updates.
- **Internationalization (i18n)**: Supports English (`en`), Persian (`fa`), and Arabic (`ar`) translations.
- **Modular Architecture**: DDD-inspired structure with adapters, domain, and infrastructure layers.
- **Observability**: Structured JSON logging with `structlog` for monitoring.
- **Security**: CORS, JWT-ready authentication, and secret key validation (minimum 32 characters).
- **Database**: PostgreSQL 16 with persistent storage, connection pooling, and secure SSL connections.
- **Caching/Messaging**: Redis 7.2 with persistent storage and secure TLS connections.
- **Environment Management**: Configurations for `development`, `staging`, `production`, and `test` via `.env.*` files.
- **Dockerized Deployment**: Live reloading in development, optimized multi-stage builds for production.
- **CI/CD Readiness**: Testing, linting, and pre-commit hooks for code quality.

## Installation

### Prerequisites
- **Python 3.12.7**: Verify with `python --version`.
- **Poetry 1.8.3**: Install with `pip install poetry`.
- **Docker**: Latest Docker Desktop or CLI (optional for development/test if using local PostgreSQL/Redis).
- **PostgreSQL**: Version 16 for external servers (staging/production) or local instances (development/test).
- **Redis**: Version 7.2 for external servers (staging/production) or local instances (development/test).
- **Git**: Latest version (verify with `git --version`).
- **Editor**: VS Code for live code changes.

### Steps
1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd cedrina
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
   - Update `.env` with a unique `SECRET_KEY` (at least 32 characters, e.g., generated with `openssl rand -base64 32`), PostgreSQL credentials (`POSTGRES_*`), and Redis credentials (`REDIS_*`).
   - Set `ENABLE_LOCAL_POSTGRES=true` and `ENABLE_LOCAL_REDIS=true` to use local PostgreSQL and Redis instances (e.g., `POSTGRES_HOST=localhost`, `REDIS_HOST=localhost`), or set to `false` to use Dockerized containers.
   - Other environments (`staging`, `production`, `test`) use `.env.<env>` files included in the repository.

4. **Compile Translations**:
   ```bash
   make compile-translations
   ```

5. **Initialize Database and Cache**:
   - For development/test with `ENABLE_LOCAL_POSTGRES=true` and `ENABLE_LOCAL_REDIS=true`, ensure local PostgreSQL and Redis instances are running and configured in `.env` or `.env.test`:
     ```bash
     psql -U postgres -c "CREATE DATABASE cedrina_dev;"
     psql -U postgres -c "CREATE DATABASE cedrina_test;"
     redis-cli -h localhost -p 6379 ping
     ```
     Run without Dockerized services:
     ```bash
     make run-dev
     ```
   - For development/test with `ENABLE_LOCAL_POSTGRES=false` and `ENABLE_LOCAL_REDIS=false`, Docker Compose manages PostgreSQL and Redis containers with persistent storage. Enable the `postgres` and `redis` profiles:
     ```bash
     COMPOSE_PROFILES=postgres,redis make run-dev
     ```
   - For staging/production, configure external PostgreSQL and Redis servers (e.g., AWS RDS, ElastiCache) with SSL and update `.env.<env>` with credentials:
     ```bash
     psql -U postgres -h staging-postgres.example.com -c "CREATE DATABASE cedrina_staging;"
     ```
   - Apply migrations:
     ```bash
     make db-migrate
     ```

6. **Install Pre-Commit Hooks**:
   ```bash
   poetry run pre-commit install
   ```

## Running the Application

### Local Development (Without Docker)
1. Ensure PostgreSQL and Redis are running locally (if `ENABLE_LOCAL_POSTGRES=true` or `ENABLE_LOCAL_REDIS=true`).
2. Activate the Poetry environment:
   ```bash
   poetry shell
   ```
3. Ensure `.env` is set up with valid PostgreSQL and Redis credentials.
4. Run the application:
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
2. Set `ENABLE_LOCAL_POSTGRES=false` and `ENABLE_LOCAL_REDIS=false` in `.env` to use Dockerized PostgreSQL and Redis containers, or set to `true` and configure `POSTGRES_HOST` and `REDIS_HOST` for local instances.
3. Run Docker Compose:
   - With Dockerized PostgreSQL and Redis containers:
     ```bash
     COMPOSE_PROFILES=postgres,redis make run-dev
     ```
   - With local instances:
     ```bash
     make run-dev
     ```
   - Mounts `src/` and `locales/` for live reloading.
   - Uses persistent volumes (`cedrina_postgres_data`, `cedrina_redis_data`) if Dockerized services are enabled.
   - Edit code in `src/` or `locales/`, and recompile translations if needed (`make compile-translations`).
4. Access the same endpoints as above.

### Staging
1. Configure `.env.staging` with credentials for external PostgreSQL and Redis servers (e.g., AWS RDS, ElastiCache). Do not use `docker-compose.yml` for staging.
2. Build the Docker image:
   ```bash
   make build
   ```
3. Run the container:
   ```bash
   make run-staging
   ```
4. Access at `https://staging.example.com/api/v1/health` (configure DNS/load balancer).

### Production
1. Configure `.env.production` with credentials for external PostgreSQL and Redis servers. Do not use `docker-compose.yml` for production.
2. Build the Docker image:
   ```bash
   make build
   ```
3. Run the container:
   ```bash
   make run-prod
   ```
4. Access at `https://example.com/api/v1/health` (configure DNS/load balancer).

## Testing
Unit and integration tests ensure reliability, including database and cache connectivity.

### Running Tests
1. Ensure `.env.test` exists with valid PostgreSQL and Redis credentials.
2. Set `ENABLE_LOCAL_POSTGRES=true` and `ENABLE_LOCAL_REDIS=true` in `.env.test` for local test instances, or set to `false` for Dockerized test databases.
3. Run tests with coverage:
   - With Dockerized PostgreSQL and Redis containers:
     ```bash
     COMPOSE_PROFILES=postgres,redis make test
     ```
   - With local instances:
     ```bash
     make test
     ```
   - Uses `.env.test` for the test environment.
   - Tests translations, database, and cache connectivity.
   - View coverage report in `htmlcov/index.html`.
3. Tests are in:
   - `tests/unit/`: Unit tests (e.g., `test_database.py`).
   - `tests/integration/`: Integration tests (to be added).

### Test Configuration
- `pytest.ini` sets `pythonpath = src` for module resolution and loads `.env.test` via `pytest-dotenv`.
- Async tests are supported with `pytest-asyncio`.

### Troubleshooting Tests
- **ModuleNotFoundError**: Verify `pytest.ini` exists and `pythonpath = src` is set.
- **Validation Errors**: Ensure `.env.test` has a `SECRET_KEY` with at least 32 characters and valid `POSTGRES_*` and `REDIS_*` settings.
- **Database Errors**: Check PostgreSQL connectivity and credentials in `.env.test`.
  - For local PostgreSQL, ensure the server is running:
    ```bash
    psql -U cedrina_test -d cedrina_test -h localhost
    ```
- **Cache Errors**: Check Redis connectivity:
  - For local Redis, ensure the server is running:
    ```bash
    redis-cli -h localhost -p 6379 ping
    ```
- **Translation Errors**:
  - Verify `messages.mo` files exist in `locales/<lang>/LC_MESSAGES/`.
  - Run `make compile-translations` after editing `.po` files.
  - Check logs for `i18n_initialized` and `translation_fetched` messages.
- **Cache Issues**: Clear pytest cache:
  ```bash
  rm -rf .pytest_cache
  ```

## Internationalization (i18n)
- **Supported Languages**: English (`en`), Persian (`fa`), and Arabic (`ar`).
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

## Database and Cache Management
- **PostgreSQL**: Version 16, used for all environments with persistent storage and secure connections.
- **Redis**: Version 7.2, used for caching or messaging with persistent storage and secure TLS connections.
- **Development**:
  - Local instances (enable with `ENABLE_LOCAL_POSTGRES=true` and `ENABLE_LOCAL_REDIS=true`, using `POSTGRES_HOST=localhost`, `REDIS_HOST=localhost`).
  - Dockerized containers (enable with `ENABLE_LOCAL_POSTGRES=false` and `ENABLE_LOCAL_REDIS=false`, using `COMPOSE_PROFILES=postgres,redis`).
  - Persistent volumes (`cedrina_postgres_data`, `cedrina_redis_data`) retain data when using containers.
- **Test**:
  - Local instances (default with `ENABLE_LOCAL_POSTGRES=true` and `ENABLE_LOCAL_REDIS=true`).
  - Dockerized test databases (enable with `ENABLE_LOCAL_POSTGRES=false` and `ENABLE_LOCAL_REDIS=false`).
- **Staging/Production**: Connects to external PostgreSQL and Redis servers (e.g., AWS RDS, ElastiCache) with SSL, backups, and high availability. Use `.env.staging` or `.env.production` without `docker-compose.yml`.
- **Migrations**:
  - Apply migrations:
    ```bash
    make db-migrate
    ```
  - Roll back migrations:
    ```bash
    make db-rollback
    ```
- **Setup**:
  - For development/test with local instances:
    ```bash
    psql -U postgres -c "CREATE DATABASE cedrina_dev;"
    psql -U postgres -c "CREATE DATABASE cedrina_test;"
    redis-cli -h localhost -p 6379 ping
    make run-dev
    ```
  - For development/test with Dockerized containers:
    ```bash
    COMPOSE_PROFILES=postgres,redis make run-dev
    ```
  - For staging/production, configure external servers and update `.env.<env>`:
    ```bash
    psql -U postgres -h staging-postgres.example.com -c "CREATE DATABASE cedrina_staging;"
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
   docker tag cedrina:latest <registry>/cedrina:0.2.0
   ```

### Releasing
1. Push to the registry:
   ```bash
   docker push <registry>/cedrina:0.2.0
   ```
2. Deploy:
   - Pull the image:
     ```bash
     docker pull <registry>/cedrina:0.2.0
     ```
   - Run:
     ```bash
     make run-staging  # or make run-prod
     ```

### Rollback
- Redeploy a previous image:
  ```bash
  docker run -d -p 8000:8000 --env-file .env.production <registry>/cedrina:0.1.0
  ```

## Directory Structure
- **src/**: Application code
  - **adapters/**: REST (`api/v1`) and WebSockets (`websockets`).
  - **core/**: `config`, `logging`, `dependencies`.
  - **domain/**: `entities`, `services` (DDD).
  - **infrastructure/**: `database`, future brokers.
  - **utils/**: Helpers, including `i18n.py`.
- **locales/**: Translation files (`en`, `fa`, `ar`).
- **alembic/**: Database migrations.
- **tests/**: `unit`, `integration`.
- **scripts/**: Utility scripts.
- **docs/**: Documentation.
- **.env.<env>**: `development`, `staging`, `production`, `test`.

## Environment Configuration
- **.env.development**: Local development, copy to `.env`, includes PostgreSQL and Redis credentials with `ENABLE_LOCAL_POSTGRES` and `ENABLE_LOCAL_REDIS`.
- **.env.staging**: Staging, connects to external PostgreSQL and Redis servers with SSL.
- **.env.production**: Production, connects to external PostgreSQL and Redis servers with SSL.
- **.env.test**: Testing, local or Dockerized databases.
- Update `SECRET_KEY` (minimum 32 characters), `ALLOWED_ORIGINS`, `POSTGRES_*`, and `REDIS_*` fields in each file.
- Example `SECRET_KEY` or `POSTGRES_PASSWORD`/`REDIS_PASSWORD` generation:
  ```bash
  openssl rand -base64 32
  ```

## Troubleshooting
- **ValidationError (SECRET_KEY, POSTGRES_PASSWORD, REDIS_PASSWORD)**:
  - Ensure `SECRET_KEY` (32+ characters), `POSTGRES_PASSWORD` (12+ characters), and `REDIS_PASSWORD` (12+ characters) in `.env` or `.env.<env>`.
- **ModuleNotFoundError**:
  - Use `make run-local` or `make test` to set `PYTHONPATH`.
  - In Docker, `PYTHONPATH=/app` is set automatically.
- **Database Connectivity**:
  - For `ENABLE_LOCAL_POSTGRES=true`, ensure the local PostgreSQL server is running:
    ```bash
    psql -U cedrina_dev -d cedrina_dev -h localhost
    ```
  - For `ENABLE_LOCAL_POSTGRES=false`, verify the Dockerized PostgreSQL container:
    ```bash
    docker ps
    ```
  - Check logs:
    ```bash
    docker logs <postgres_container_id>
    ```
- **Cache Connectivity**:
  - For `ENABLE_LOCAL_REDIS=true`, ensure the local Redis server is running:
    ```bash
    redis-cli -h localhost -p 6379 ping
    ```
  - For `ENABLE_LOCAL_REDIS=false`, verify the Dockerized Redis container:
    ```bash
    docker ps
    ```
  - Check logs:
    ```bash
    docker logs <redis_container_id>
    ```
- **Profile Issues**:
  - If Dockerized services don’t start, verify `ENABLE_LOCAL_POSTGRES=false`, `ENABLE_LOCAL_REDIS=false`, and `COMPOSE_PROFILES`:
    ```bash
    cat .env | grep ENABLE_LOCAL
    echo $COMPOSE_PROFILES
    ```
  - Set explicitly if needed:
    ```bash
    export COMPOSE_PROFILES=postgres,redis
    ```
- **Translation Issues**:
  - If `health_status_ok` persists, verify `messages.mo` files in `locales/<lang>/LC_MESSAGES/`.
  - Run `make compile-translations`.
  - Check logs for `i18n_initialized` and `translation_fetched` entries (share for further debugging).
- **Docker Volume Issues**:
  - Verify volumes:
    ```bash
    docker volume inspect cedrina_postgres_data cedrina_redis_data
    ```
  - Recreate if corrupted:
    ```bash
    docker volume rm cedrina_postgres_data cedrina_redis_data
    COMPOSE_PROFILES=postgres,redis make run-dev
    ```
- **Docker Issues**: Ensure ports are free (`docker ps`) and volumes are mounted correctly.
- **Logs**: Check JSON logs (`docker logs <container>`).

## Development Workflow
1. Configure `.env` with `ENABLE_LOCAL_POSTGRES=true` and `ENABLE_LOCAL_REDIS=true` for local instances, or `false` for Dockerized PostgreSQL and Redis containers.
2. Run `make run-dev` or `COMPOSE_PROFILES=postgres,redis make run-dev` as needed.
3. Edit `src/` or `locales/`; recompile translations if needed (`make compile-translations`).
4. Apply migrations (`make db-migrate`) after schema changes.
5. Run `make test` or `COMPOSE_PROFILES=postgres,redis make test` frequently.
6. Commit with Git, ensuring pre-commit hooks pass.
7. Push to the repository.

## Deployment Notes
- **Staging**: Use a load balancer, monitor logs, and configure external PostgreSQL and Redis servers with SSL, backups, and high availability. Do not use `docker-compose.yml`.
- **Production**: Implement auto-scaling, health checks, and automated backups for PostgreSQL and Redis servers. Do not use `docker-compose.yml`.
- **Secrets**: Use a vault (e.g., AWS Secrets Manager) for `SECRET_KEY`, `POSTGRES_PASSWORD`, and `REDIS_PASSWORD`.

## Customization
To adapt **Cedrina** for your project:
- **Rename the Project**:
  - Update `name` in `pyproject.toml`.
  - Replace `cedrina` in `Dockerfile`, `docker-compose.yml`, and build commands.
- **Add Endpoints**: Extend `src/adapters/api/v1/` with new routes.
- **Expand i18n**: Add languages by creating new `locales/<lang>/LC_MESSAGES/messages.po` files and updating `SUPPORTED_LANGUAGES` in `settings.py`.
- **Integrate Database Models**: Define SQLModel models in `src/domain/entities/` and create migrations with Alembic.

## Future Enhancements
- Database model integration (e.g., User model with SQLModel).
- Redis-based features (e.g., caching, pub/sub messaging).
- JWT authentication.
- Message broker (Redis, RabbitMQ).
- Monitoring (Prometheus, Grafana).
- Additional languages for i18n.

---

This document is for internal team use only. Contact the architecture team for support.