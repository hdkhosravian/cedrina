# Cedrina Makefile
# Comprehensive tasks for building, running, testing, and maintaining the Cedrina FastAPI project.

.PHONY: all build build-prod run-dev run-dev-local run-test run-staging run-prod test lint format compile-translations update-translations db-migrate db-rollback db-init clean clean-volumes check-health

# Default target: build and run development
all: build compile-translations run-dev

# Build the Docker image for development
build:
	@echo "Building Cedrina development Docker image..."
	docker build --no-cache -t cedrina:development -f Dockerfile .

# Build the Docker image for staging/production
build-prod:
	@echo "Building Cedrina staging/production Docker image..."
	docker build --no-cache -t cedrina:${APP_ENV:-production} -f Dockerfile.prod .

# Run development environment with Docker Compose
run-dev:
	@echo "Starting development environment..."
	APP_ENV=development docker-compose -f docker-compose.yml up --build --force-recreate

# Run development environment locally without Docker
run-dev-local:
	@echo "Starting local development server..."
	poetry run bash -c "export PYTHONPATH=\$$PWD && uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload"

# Run test environment with Docker Compose
run-test:
	@echo "Starting test environment..."
	poetry run bash -c "export PYTHONPATH=\$$PWD && pytest --cov=src --cov-report=html"

# Run staging environment with external services
run-staging:
	@echo "Starting staging environment..."
	@if [ -f .env.staging ]; then \
		APP_ENV=staging docker-compose -f docker-compose.prod.yml up --build --force-recreate; \
	else \
		echo "Error: .env.staging file not found"; \
		exit 1; \
	fi

# Run production environment with external services
run-prod:
	@echo "Starting production environment..."
	@if [ -f .env.production ]; then \
		APP_ENV=production docker-compose -f docker-compose.prod.yml up --build --force-recreate; \
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
	@echo "Initializing databases..."
	@echo "PostgreSQL and Redis are managed by Docker Compose; ensure docker-compose.yml is configured."

# Clean up Docker resources
clean:
	@echo "Cleaning up Docker resources..."
	docker-compose -f docker-compose.yml down --remove-orphans --volumes --rmi all
	docker-compose -f docker-compose.prod.yml down --remove-orphans --rmi all
	@docker system prune -f --all
	@docker volume prune -f
	@docker network prune -f
	@docker builder prune -f

# Clean up persistent volumes
clean-volumes:
	@echo "Removing persistent volumes..."
	@if [ "$$(docker volume ls -q -f name=cedrina_postgres_data)" ]; then \
		docker volume rm cedrina_postgres_data || true; \
	fi
	@if [ "$$(docker volume ls -q -f name=cedrina_redis_data)" ]; then \
		docker volume rm cedrina_redis_data || true; \
	fi

# Check service health (development only)
check-health:
	@echo "Checking service health..."
	@docker inspect --format='{{.State.Health.Status}}' cedrina_postgres_1 || echo "PostgreSQL service not running"
	@docker inspect --format='{{.State.Health.Status}}' cedrina_redis_1 || echo "Redis service not running"
