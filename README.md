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
- **Docker**: Latest Docker Desktop or CLI (required for development/test; optional for staging/production with external services).
- **PostgreSQL**: Version 16 for external servers (staging/production) or Dockerized instances (development/test).
- **Redis**: Version 7.2 for external servers (staging/production) or Dockerized instances (development/test).
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
   - For development/test, ensure `.env.development` is configured with Dockerized service credentials:
     ```bash
     cp .env.development .env
     ```
     - Update with a unique `SECRET_KEY` (generate with `openssl rand -base64 32`), PostgreSQL credentials (`POSTGRES_*`), Redis credentials (`REDIS_*`), and `CEDRINA_DEV_PASSWORD`.
     - Use `POSTGRES_HOST=postgres` and `REDIS_HOST=redis` for Dockerized services.
   - For staging/production, configure `.env.staging` or `.env.production` with external PostgreSQL and Redis server credentials (e.g., AWS RDS, ElastiCache).

4. **Compile Translations**:
   ```bash
   make compile-translations
   ```

5. **Initialize Database and Cache**:
   - For development/test, Docker Compose manages PostgreSQL and Redis containers:
     ```bash
     make run-dev
     ```
   - For staging/production, set up external servers and update `.env.<env>`:
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
This mode runs the application locally using Uvicorn, suitable for quick iteration without Docker overhead. Note that PostgreSQL and Redis must be available locally or accessible remotely.

1. **Configure Environment**:
   - Copy `.env.development` to `.env`:
     ```bash
     cp .env.development .env
     ```
   - Update `.env` with:
     - `SECRET_KEY`: Generate with `openssl rand -base64 32`.
     - `POSTGRES_HOST`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB=cedrina_dev` (e.g., `localhost` for local PostgreSQL).
     - `REDIS_HOST`, `REDIS_PORT=6379` (e.g., `localhost` for local Redis).
     - `CEDRINA_DEV_PASSWORD` for the `cedrina_dev` database role.
     - Example `DATABASE_URL`: `postgresql+psycopg2://postgres:postgres@localhost:5432/cedrina_dev?sslmode=disable`

2. **Set Up Local Services**:
   - Start local PostgreSQL and Redis instances:
     ```bash
     psql -U postgres -c "CREATE DATABASE cedrina_dev;"
     redis-cli -h localhost -p 6379 ping
     ```
   - Verify connectivity:
     ```bash
     psql -U postgres -d cedrina_dev -h localhost
     redis-cli -h localhost -p 6379 ping
     ```

3. **Run the Application**:
   - Activate the Poetry environment:
     ```bash
     poetry shell
     ```
   - Start the server:
     ```bash
     make run-dev-local
     ```
     - Uses Uvicorn with hot reloading for live code updates.
     - Sets `PYTHONPATH=/app` automatically.

4. **Access Endpoints**:
   - REST: `http://localhost:8000/api/v1/health` (returns `{"status":"ok","env":"development","message":"System is operational"}`)
   - With language: `http://localhost:8000/api/v1/health?lang=fa` (Persian message)
   - WebSocket: `ws://localhost:8000/ws/health?lang=ar` (Arabic message)
   - Docs: `http://localhost:8000/docs` (if `DEBUG=true`)

### Development with Docker
This mode uses Docker Compose to run the application, PostgreSQL, and Redis containers, providing a consistent development environment with live reloading.

1. **Configure Environment**:
   - Ensure `.env.development` is configured with:
     - `SECRET_KEY`: Generate with `openssl rand -base64 32`.
     - `POSTGRES_HOST=postgres`, `POSTGRES_PORT=5432`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB=cedrina_dev`.
     - `REDIS_HOST=redis`, `REDIS_PORT=6379`.
     - `CEDRINA_DEV_PASSWORD` for the `cedrina_dev` database role.
     - Example `DATABASE_URL`: `postgresql+psycopg2://postgres:postgres@postgres:5432/cedrina_dev?sslmode=disable`

2. **Build and Run**:
   - Build the development Docker image:
     ```bash
     make build
     ```
   - Start the application and services:
     ```bash
     make run-dev
     ```
     - Uses `docker-compose.yml` to start `app`, `postgres`, and `redis` services.
     - Mounts `src/` for live code updates (edit files in `src/` to see changes instantly).
     - Uses persistent volumes (`cedrina_postgres_data`, `cedrina_redis_data`).

3. **Access Endpoints**:
   - Same as Local Development (REST, WebSocket, Docs).
   - Verify container status:
     ```bash
     docker ps
     ```

4. **Update Translations**:
   - If `locales/` changes, recompile translations:
     ```bash
     make compile-translations
     ```

### Testing
This mode runs unit and integration tests to ensure application reliability, using Dockerized PostgreSQL and Redis for consistency.

1. **Configure Environment**:
   - Ensure `.env` is configured with:
     - `SECRET_KEY`, `POSTGRES_*`, `REDIS_*`, `CEDRINA_DEV_PASSWORD`.
     - `POSTGRES_HOST=postgres`, `REDIS_HOST=redis` for Dockerized services.
     - Example `DATABASE_URL`: `postgresql+psycopg2://postgres:postgres@postgres:5432/cedrina_test?sslmode=disable`

2. **Set Up Test Database**:
   - Docker Compose manages the test database:
     ```bash
     APP_ENV=test make run-dev
     ```

3. **Run Tests**:
   - Start Dockerized services and run tests:
     ```bash
     APP_ENV=test make run-dev
     make test
     ```
     - Uses `pytest` with coverage, testing translations, database, and Redis connectivity.
     - View coverage report: `htmlcov/index.html`.

4. **Verify**:
   - Check test output for failures.
   - Ensure `tests/unit/` and `tests/integration/` run successfully.

### Staging
This mode deploys the application to a staging environment, connecting to external PostgreSQL and Redis servers with secure configurations.

1. **Configure Environment**:
   - Edit `.env.staging` with credentials for external PostgreSQL and Redis servers (e.g., AWS RDS, ElastiCache):
     - `SECRET_KEY`: Generate with `openssl rand -base64 32`.
     - `POSTGRES_HOST`, `POSTGRES_PORT=5432`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB=cedrina_staging`, `POSTGRES_SSL_MODE=require`.
     - `REDIS_HOST`, `REDIS_PORT=6379`, `REDIS_PASSWORD`, `REDIS_SSL=true`.
     - `CEDRINA_DEV_PASSWORD` for the `cedrina_dev` database role.
     - Example:
       ```plaintext
       DATABASE_URL=postgresql+psycopg2://postgres:your_staging_password@staging.db.example.com:5432/cedrina_staging?sslmode=require
       REDIS_URL=rediss://:your_staging_redis_password@staging.redis.example.com:6379/0
       ```

2. **Set Up External Services**:
   - Create the staging database:
     ```bash
     psql -U postgres -h staging.db.example.com -c "CREATE DATABASE cedrina_staging;"
     ```
   - Verify Redis connectivity:
     ```bash
     redis-cli -h staging.redis.example.com -p 6379 -a your_staging_redis_password --tls ping
     ```

3. **Build and Run**:
   - Build the production-optimized image:
     ```bash
     make build-prod
     ```
   - Start the application:
     ```bash
     make run-staging
     ```
     - Uses `docker-compose.prod.yml` and `Dockerfile.prod` for a secure, minimal image with non-root user and Gunicorn workers.

4. **Access Endpoints**:
   - REST: `https://staging.example.com/api/v1/health` (configure DNS/load balancer).
   - WebSocket: `wss://staging.example.com/ws/health?lang=ar`.
   - Docs: `https://staging.example.com/docs` (if enabled).

5. **Apply Migrations**:
   ```bash
   make db-migrate
   ```

### Production
This mode deploys the application to a production environment, using secure configurations for external PostgreSQL and Redis servers.

1. **Configure Environment**:
   - Edit `.env.production` with credentials for external PostgreSQL and Redis servers:
     - Same fields as `.env.staging` but with production values (e.g., `POSTGRES_DB=cedrina_production`).
     - Example:
       ```plaintext
       DATABASE_URL=postgresql+psycopg2://postgres:your_production_password@prod.db.example.com:5432/cedrina_production?sslmode=require
       REDIS_URL=rediss://:your_production_redis_password@prod.redis.example.com:6379/0
       ```

2. **Set Up External Services**:
   - Create the production database:
     ```bash
     psql -U postgres -h prod.db.example.com -c "CREATE DATABASE cedrina_production;"
     ```
   - Verify Redis connectivity:
     ```bash
     redis-cli -h prod.redis.example.com -p 6379 -a your_production_redis_password --tls ping
     ```

3. **Build and Run**:
   - Build the production-optimized image:
     ```bash
     make build-prod
     ```
   - Start the application:
     ```bash
     make run-prod
     ```
     - Uses `docker-compose.prod.yml` and `Dockerfile.prod`.

4. **Access Endpoints**:
   - REST: `https://example.com/api/v1/health` (configure DNS/load balancer).
   - WebSocket: `wss://example.com/ws/health?lang=ar`.
   - Docs: `https://example.com/docs` (if enabled).

5. **Apply Migrations**:
   ```bash
   make db-migrate
   ```

## Testing
Unit and integration tests ensure reliability, including database and cache connectivity.

### Running Tests
1. Ensure `.env` exists with valid PostgreSQL and Redis credentials.
2. Run tests with coverage:
   - With Dockerized PostgreSQL and Redis containers:
     ```bash
     COMPOSE_PROFILES=postgres,redis make test
     ```
   - With local instances:
     ```bash
     make test
     ```
   - Uses `.env` for the test environment.
   - Tests translations, database, and cache connectivity.
   - View coverage report in `htmlcov/index.html`.
3. Tests are in:
   - `tests/unit/`: Unit tests (e.g., `test_database.py`).
   - `tests/integration/`: Integration tests (to be added).

### Test Configuration
- `pytest.ini` sets `pythonpath = src` for module resolution and loads `.env` via `pytest-dotenv`.
- Async tests are supported with `pytest-asyncio`.

### Troubleshooting Tests
- **ModuleNotFoundError**: Verify `pytest.ini` exists and `pythonpath = src` is set.
- **Validation Errors**: Ensure `.env` has a `SECRET_KEY` with at least 32 characters and valid `POSTGRES_*` and `REDIS_*` settings.
- **Database Errors**: Check PostgreSQL connectivity and credentials in `.env`.
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
  - Dockerized containers (`POSTGRES_HOST=postgres`, `REDIS_HOST=redis`) via `docker-compose.yml`.
  - Persistent volumes (`cedrina_postgres_data`, `cedrina_redis_data`) retain data.
- **Test**:
  - Dockerized test databases (`POSTGRES_HOST=postgres`, `REDIS_HOST=redis`).
- **Staging/Production**: Connects to external PostgreSQL and Redis servers (e.g., AWS RDS, ElastiCache) with SSL, backups, and high availability. Use `.env.staging` or `.env.production` with `docker-compose.prod.yml`.
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
  - For development/test, Docker Compose creates databases:
    ```bash
    make run-dev
    ```
  - For staging/production, configure external servers:
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
   - Development:
     ```bash
     make build
     ```
   - Staging/Production:
     ```bash
     make build-prod
     ```
4. Tag the image:
   ```bash
   docker tag cedrina:${APP_ENV:-production} <registry>/cedrina:0.2.0
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
- **.env.development**: Development, includes Dockerized PostgreSQL/Redis credentials.
- **.env.staging**: Staging, connects to external PostgreSQL/Redis with SSL.
- **.env.production**: Production, connects to external PostgreSQL/Redis with SSL.
- Update `SECRET_KEY` (minimum 32 characters), `ALLOWED_ORIGINS`, `POSTGRES_*`, `REDIS_*`, and `CEDRINA_DEV_PASSWORD` in each file.
- Example `SECRET_KEY` or password generation:
  ```bash
  openssl rand -base64 32
  ```

## Troubleshooting
- **ValidationError (SECRET_KEY, POSTGRES_PASSWORD, REDIS_PASSWORD)**:
  - Ensure `SECRET_KEY` (32+ characters), `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, and `CEDRINA_DEV_PASSWORD` are set in `.env.*`.
- **ModuleNotFoundError**:
  - Use `make run-dev-local` or `make test` to set `PYTHONPATH`.
  - In Docker, `PYTHONPATH=/app` is set automatically.
- **Database Connectivity**:
  - Development/Test: Verify Dockerized PostgreSQL container:
    ```bash
    docker ps
    docker logs cedrina_postgres_1
    ```
  - Staging/Production: Verify external server:
    ```bash
    psql -U postgres -h staging  -d cedrina_staging
    ```
- **Cache Connectivity**:
  - Development/Test: Verify Dockerized Redis container:
    ```bash
    docker ps
    docker logs cedrina_redis_1
    ```
  - Staging/Production: Verify external Redis:
    ```bash
    redis-cli -h staging.redis.example.com -p 6379 -a your_staging_redis_password --tls ping
    ```
- **Translation Issues**:
  - Verify `messages.mo` in `locales/<lang>/LC_MESSAGES/`.
  - Run `make compile-translations`.
  - Check logs for `i18n_initialized`.
- **Docker Volume Issues**:
  - Verify volumes:
    ```bash
    docker volume inspect cedrina_postgres_data cedrina_redis_data
    ```
  - Recreate if corrupted:
    ```bash
    make clean-volumes
    make run-dev
    ```
- **Logs**: Check JSON logs (`docker logs <container>`).

## Development Workflow
1. Configure `.env.development` for Dockerized services.
2. Run `make run-dev` for development.
3. Edit `src/` or `locales/`; recompile translations (`make compile-translations`).
4. Apply migrations (`make db-migrate`) after schema changes.
5. Run `make test` frequently.
6. Commit with Git, ensuring pre-commit hooks pass.
7. Push to the repository.

## Deployment Notes
- **Staging**: Use load balancer, monitor logs, and configure external PostgreSQL/Redis with SSL, backups, and high availability.
- **Production**: Implement auto-scaling, health checks, and automated backups.
- **Secrets**: Use a vault (e.g., AWS Secrets Manager) for `SECRET_KEY`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, and `CEDRINA_DEV_PASSWORD`.

## Customization
- **Rename Project**:
  - Update `name` in `pyproject.toml`.
  - Replace `cedrina` in `Dockerfile`, `docker-compose.yml`, `docker-compose.prod.yml`.
- **Add Endpoints**: Extend `src/adapters/api/v1/`.
- **Expand i18n**: Add languages in `SUPPORTED_LANGUAGES` and `locales/<lang>/`.
- **Database Models**: Define SQLModel models in `src/domain/entities/` and generate migrations.

## Future Enhancements
- Database model integration (e.g., User model).
- Redis pub/sub or caching.
- JWT authentication.
- Message broker (Redis, RabbitMQ).
- Monitoring (Prometheus, Grafana).
- Additional i18n languages.

---

This document is for internal team use only. Contact the architecture team for support.