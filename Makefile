# Cedrina Makefile
# Comprehensive tasks for building, running, testing, and maintaining the Cedrina FastAPI project.
# Supports conditional PostgreSQL and Redis services, i18n, and enterprise-grade deployment.

.PHONY: all build run-dev run-dev-local run-test run-staging run-prod test lint format compile-translations update-translations db-migrate db-rollback db-init clean clean-volumes check-health

# Default target: build, compile translations, and run development
all: build compile-translations run-dev

# Build the Docker image for Cedrina
build:
	@echo "Building Cedrina Docker image..."
	docker build --no-cache -t cedrina:latest .

# Run development environment with Docker Compose, using profiles based on ENABLE_LOCAL_* settings
run-dev:
	@echo "Starting development environment..."
	@PROFILES=""; \
	if [ "$$(grep -E '^ENABLE_LOCAL_POSTGRES=false' .env 2>/dev/null || echo false)" = "false" ]; then \
		echo "Using local PostgreSQL instance (ENABLE_LOCAL_POSTGRES=true)"; \
	else \
		echo "Using Dockerized PostgreSQL (ENABLE_LOCAL_POSTGRES=false)"; \
		PROFILES="postgres"; \
	fi; \
	if [ "$$(grep -E '^ENABLE_LOCAL_REDIS=false' .env 2>/dev/null || echo false)" = "false" ]; then \
		echo "Using local Redis instance (ENABLE_LOCAL_REDIS=true)"; \
	else \
		echo "Using Dockerized Redis (ENABLE_LOCAL_REDIS=false)"; \
		PROFILES="$$PROFILES$${PROFILES:+,}redis"; \
	fi; \
	if [ -z "$$PROFILES" ]; then \
		docker-compose up --build; \
	else \
		COMPOSE_PROFILES=$$PROFILES docker-compose up --build; \
	fi

# Run development environment locally without Docker
run-dev-local:
	@echo "Starting local development server..."
	poetry run bash -c "export PYTHONPATH=\$$PWD && uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload"

# Run test environment with Docker Compose, using profiles based on ENABLE_LOCAL_* settings
run-test:
	@echo "Starting test environment..."
	@PROFILES=""; \
	if [ "$$(grep -E '^ENABLE_LOCAL_POSTGRES=false' .env.test 2>/dev/null || echo false)" = "false" ]; then \
		echo "Using local PostgreSQL instance for tests (ENABLE_LOCAL_POSTGRES=true)"; \
	else \
		echo "Using Dockerized PostgreSQL for tests (ENABLE_LOCAL_POSTGRES=false)"; \
		PROFILES="postgres"; \
	fi; \
	if [ "$$(grep -E '^ENABLE_LOCAL_REDIS=false' .env.test 2>/dev/null || echo false)" = "false" ]; then \
		echo "Using local Redis instance for tests (ENABLE_LOCAL_REDIS=true)"; \
	else \
		echo "Using Dockerized Redis for tests (ENABLE_LOCAL_REDIS=false)"; \
		PROFILES="$$PROFILES$${PROFILES:+,}redis"; \
	fi; \
	if [ -z "$$PROFILES" ]; then \
		poetry run bash -c "export PYTHONPATH=\$$PWD && pytest --cov=src --cov-report=html"; \
	else \
		COMPOSE_PROFILES=$$PROFILES poetry run bash -c "export PYTHONPATH=\$$PWD && pytest --cov=src --cov-report=html"; \
	fi

# Run staging environment with external PostgreSQL and Redis servers
run-staging:
	@echo "Starting staging environment..."
	@if [ -f .env.staging ]; then \
		docker run -d -p 8000:8000 --env-file .env.staging cedrina:latest; \
	else \
		echo "Error: .env.staging file not found"; \
		exit 1; \
	fi

# Run production environment with external PostgreSQL and Redis servers
run-prod:
	@echo "Starting production environment..."
	@if [ -f .env.production ]; then \
		docker run -d -p 8000:8000 --env-file .env.production cedrina:latest; \
	else \
		echo "Error: .env.production file not found"; \
		exit 1; \
	fi

# Run tests with coverage
test:
	@echo "Running tests..."
	$(MAKE) run-test

# Run linting with Ruff and MyPy
lint:
	@echo "Running linting..."
	poetry run ruff check src tests
	poetry run mypy src tests

# Format code with Black and fix Ruff issues
format:
	@echo "Formatting code..."
	poetry run black src tests
	poetry run ruff check --fix src tests

# Compile translations
compile-translations:
	@echo "Compiling translations..."
	poetry run pybabel compile -d locales -D messages

# Update translation files
update-translations:
	@echo "Updating translations..."
	poetry run pybabel extract -F babel.cfg -o locales/messages.pot src/
	poetry run pybabel update -i locales/messages.pot -d locales -D messages

# Apply database migrations
db-migrate:
	@echo "Applying database migrations..."
	poetry run alembic upgrade head

# Roll back the last database migration
db-rollback:
	@echo "Rolling back last database migration..."
	poetry run alembic downgrade -1

# Initialize local PostgreSQL and Redis databases for development/test
db-init:
	@echo "Initializing local databases..."
	@if [ "$$(grep -E '^ENABLE_LOCAL_POSTGRES=true' .env 2>/dev/null || echo false)" = "true" ]; then \
		echo "Creating PostgreSQL development database..."; \
		psql -U $${POSTGRES_USER:-cedrina_dev} -h $${POSTGRES_HOST:-localhost} -c "CREATE DATABASE $${POSTGRES_DB:-cedrina_dev};" || echo "Failed to create PostgreSQL database; ensure local server is running"; \
	else \
		echo "Skipping PostgreSQL initialization (ENABLE_LOCAL_POSTGRES=false)"; \
	fi
	@if [ "$$(grep -E '^ENABLE_LOCAL_REDIS=true' .env 2>/dev/null || echo false)" = "true" ]; then \
		echo "Checking local Redis instance..."; \
		redis-cli -h $${REDIS_HOST:-localhost} -p $${REDIS_PORT:-6379} -a $${REDIS_PASSWORD:-dev_redis_secure_password_123456789012} ping || echo "Failed to connect to Redis; ensure local server is running"; \
	else \
		echo "Skipping Redis initialization (ENABLE_LOCAL_REDIS=false)"; \
	fi
	@if [ "$$(grep -E '^ENABLE_LOCAL_POSTGRES=true' .env.test 2>/dev/null || echo false)" = "true" ]; then \
		echo "Creating PostgreSQL test database..."; \
		psql -U $${POSTGRES_USER:-cedrina_test} -h $${POSTGRES_HOST:-localhost} -c "CREATE DATABASE $${POSTGRES_DB:-cedrina_test};" || echo "Failed to create PostgreSQL test database; ensure local server is running"; \
	else \
		echo "Skipping PostgreSQL test initialization (ENABLE_LOCAL_POSTGRES=false)"; \
	fi
	@if [ "$$(grep -E '^ENABLE_LOCAL_REDIS=true' .env.test 2>/dev/null || echo false)" = "true" ]; then \
		echo "Checking local Redis test instance..."; \
		redis-cli -h $${REDIS_HOST:-localhost} -p $${REDIS_PORT:-6379} -a $${REDIS_PASSWORD:-test_redis_secure_password_123456789012} ping || echo "Failed to connect to Redis; ensure local server is running"; \
	else \
		echo "Skipping Redis test initialization (ENABLE_LOCAL_REDIS=false)"; \
	fi

# Clean up Docker resources (containers, images, volumes)
clean:
	@echo "Cleaning up Docker resources..."
	docker-compose down --remove-orphans
	@if [ "$$(docker images -q cedrina:latest)" ]; then \
		docker rmi cedrina:latest || true; \
	fi

# Clean up persistent volumes
clean-volumes:
	@echo "Removing persistent volumes..."
	@if [ "$$(docker volume ls -q -f name=cedrina_postgres_data)" ]; then \
		docker volume rm cedrina_postgres_data || true; \
	fi
	@if [ "$$(docker volume ls -q -f name=cedrina_redis_data)" ]; then \
		docker volume rm cedrina_redis_data || true; \
	fi

# Check service health (PostgreSQL and Redis)
check-health:
	@echo "Checking service health..."
	@if [ "$$(grep -E '^ENABLE_LOCAL_POSTGRES=false' .env 2>/dev/null || echo false)" = "false" ]; then \
		echo "Skipping PostgreSQL health check (ENABLE_LOCAL_POSTGRES=true)"; \
	else \
		docker inspect --format='{{.State.Health.Status}}' cedrina_postgres_1 || echo "PostgreSQL service not running"; \
	fi
	@if [ "$$(grep -E '^ENABLE_LOCAL_REDIS=false' .env 2>/dev/null || echo false)" = "false" ]; then \
		echo "Skipping Redis health check (ENABLE_LOCAL_REDIS=true)"; \
	else \
		docker inspect --format='{{.State.Health.Status}}' cedrina_redis_1 || echo "Redis service not running"; \
	fi
