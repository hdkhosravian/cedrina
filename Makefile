# Cedrina Makefile
# Tasks for building, running, testing, and maintaining the Cedrina FastAPI project.

.PHONY: all build build-prod run-dev run-dev-local run-test run-staging run-prod test lint format compile-translations update-translations db-migrate db-rollback db-init db-drop clean clean-volumes check-health

# Set PYTHONPATH to include project root for src/ imports
export PYTHONPATH := $(shell pwd):${PYTHONPATH}

# Default environment
APP_ENV ?= development

# Common shell command prefix for environment setup
CMD_PREFIX = set -a; . .env; export PYTHONPATH=$$PWD;

# --------------------
# Build Targets
# --------------------
all: build compile-translations run-dev
	@echo "Built and started development environment"

build:
	@echo "Building development Docker image..."
	docker build --no-cache -t cedrina:development -f Dockerfile .

build-prod:
	@echo "Building staging/production Docker image..."
	docker build --no-cache -t cedrina:${APP_ENV:-production} -f Dockerfile.prod .

# --------------------
# Run Targets
# --------------------
run-dev:
	@echo "Starting development environment..."
	APP_ENV=development docker-compose -f docker-compose.yml --env-file .env up --build --force-recreate

run-dev-local:
	@echo "Starting local development server..."
	poetry run bash -c "$(CMD_PREFIX) uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload"

run-staging:
	@echo "Starting staging environment..."
	APP_ENV=staging docker-compose -f docker-compose.prod.yml --env-file .env up --build --force-recreate

run-prod:
	@echo "Starting production environment..."
	APP_ENV=production docker-compose -f docker-compose.prod.yml --env-file .env up --build --force-recreate

# --------------------
# Test Targets
# --------------------
test:
	@echo "Running tests..."
	$(MAKE) run-test

run-test:
	@echo "Running tests in test environment..."
	@poetry run bash -c "$(CMD_PREFIX) \
		TEST_DB_URL=$$(echo \"$$DATABASE_URL\" | sed -E 's/\/[^/]+\$$/\/$$POSTGRES_DB_TEST/'); \
		export DATABASE_URL=$$TEST_DB_URL; \
		TEST_MODE=true pytest --cov=src --cov-report=html || { echo 'Error: Tests failed'; exit 1; }"

# --------------------
# Database Targets
# --------------------
db-migrate:
	@echo "Applying database migrations for $(APP_ENV)..."
	@poetry run bash -c "$(CMD_PREFIX) \
		alembic upgrade head || { echo 'Error: Migration failed for $$POSTGRES_DB'; exit 1; }"
	@if [ "$(APP_ENV)" = "development" ]; then \
		echo "Applying migrations for test database..."; \
		poetry run bash -c "$(CMD_PREFIX) \
			TEST_DB_URL=\$$(echo \"\$$DATABASE_URL\" | sed \"s/\/$$POSTGRES_DB/\/$$POSTGRES_DB_TEST/\"); \
			export DATABASE_URL=\$$TEST_DB_URL; \
			alembic upgrade head || { echo 'Error: Migration failed for $$POSTGRES_DB_TEST'; exit 1; }"; \
	fi

db-rollback:
	@echo "Rolling back last migration for $(APP_ENV)..."
	@poetry run bash -c "$(CMD_PREFIX) \
		alembic downgrade -1 || { echo 'Error: Rollback failed for $$POSTGRES_DB'; exit 1; }"
	@if [ "$(APP_ENV)" = "development" ]; then \
		echo "Rolling back test database migration..."; \
		poetry run bash -c "$(CMD_PREFIX) \
			TEST_DB_URL=$$(echo \"$$DATABASE_URL\" | sed \"s/\/$$POSTGRES_DB/\/$$POSTGRES_DB_TEST/\"); \
			export DATABASE_URL=$$TEST_DB_URL; \
			alembic downgrade -1 || { echo 'Error: Rollback failed for $$POSTGRES_DB_TEST'; exit 1; }"; \
	fi

db-init:
	@echo "Initializing database for $(APP_ENV)..."
	@poetry run bash -c "$(CMD_PREFIX) \
		psql -h $$POSTGRES_HOST -p $$POSTGRES_PORT -U $$POSTGRES_USER -c 'CREATE DATABASE $$POSTGRES_DB;' || true; \
		psql -h $$POSTGRES_HOST -p $$POSTGRES_PORT -U $$POSTGRES_USER -d $$POSTGRES_DB -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto;'"
	@if [ "$(APP_ENV)" = "development" ]; then \
		echo "Initializing test database..."; \
		poetry run bash -c "$(CMD_PREFIX) \
			psql -h $$POSTGRES_HOST -p $$POSTGRES_PORT -U $$POSTGRES_USER -c 'CREATE DATABASE $$POSTGRES_DB_TEST;' || true; \
			psql -h $$POSTGRES_HOST -p $$POSTGRES_PORT -U $$POSTGRES_USER -d $$POSTGRES_DB_TEST -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto;'"; \
	fi

db-drop:
	@echo "Dropping database for $(APP_ENV)..."
	@poetry run bash -c "$(CMD_PREFIX) \
		psql -h $$POSTGRES_HOST -p $$POSTGRES_PORT -U $$POSTGRES_USER -c 'DROP DATABASE IF EXISTS $$POSTGRES_DB;'"
	@if [ "$(APP_ENV)" = "development" ]; then \
		echo "Dropping test database..."; \
		poetry run bash -c "$(CMD_PREFIX) \
			psql -h $$POSTGRES_HOST -p $$POSTGRES_PORT -U $$POSTGRES_USER -c 'DROP DATABASE IF EXISTS $$POSTGRES_DB_TEST;'"; \
	fi

# --------------------
# Linting and Formatting
# --------------------
lint:
	@echo "Running linting..."
	poetry run ruff check src tests
	poetry run mypy src tests

format:
	@echo "Formatting code..."
	poetry run black src tests
	poetry run ruff check --fix src tests

# --------------------
# Translations
# --------------------
compile-translations:
	@echo "Compiling translations..."
	poetry run pybabel compile -d locales -D messages

update-translations:
	@echo "Updating translations..."
	poetry run pybabel extract -F babel.cfg -o locales/messages.pot src/
	poetry run pybabel update -i locales/messages.pot -d locales -D messages

# --------------------
# Cleanup
# --------------------
clean:
	@echo "Cleaning up Docker resources..."
	docker-compose -f docker-compose.yml down --remove-orphans --volumes --rmi all
	docker-compose -f docker-compose.prod.yml down --remove-orphans --rmi all
	docker system prune -f --all
	docker volume prune -f
	docker network prune -f
	docker builder prune -f

clean-volumes:
	@echo "Removing persistent volumes..."
	@docker volume rm cedrina_postgres_data || true
	@docker volume rm cedrina_redis_data || true

# --------------------
# Health Check
# --------------------
check-health:
	@echo "Checking service health..."
	@docker inspect --format='{{.State.Health.Status}}' cedrina_postgres_1 || echo "PostgreSQL service not running"
	@docker inspect --format='{{.State.Health.Status}}' cedrina_redis_1 || echo "Redis service not running"