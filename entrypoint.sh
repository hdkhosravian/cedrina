#!/bin/sh
set -e

# Function to log messages with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Set PYTHONPATH to ensure src/ imports work
export PYTHONPATH=/app:/app/src:${PYTHONPATH}
log "PYTHONPATH set to $PYTHONPATH"

# Validate required environment variables
log "Validating environment variables..."
for var in SECRET_KEY DATABASE_URL REDIS_URL POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB; do
    if [ -z "$(eval echo \$$var)" ]; then
        log "ERROR: $var is not set"
        exit 1
    fi
done

# Reconstruct DATABASE_URL to use POSTGRES_HOST from environment
if [ "$APP_ENV" = "development" ]; then
    log "Reconstructing DATABASE_URL for development..."
    export DATABASE_URL="postgresql+psycopg2://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}?sslmode=${POSTGRES_SSL_MODE}"
    log "DATABASE_URL set to $DATABASE_URL"
fi

# Wait for services based on APP_ENV
if [ "$APP_ENV" = "development" ]; then
    # Wait for PostgreSQL
    log "Waiting for PostgreSQL at postgres:5432..."
    timeout=60
    start_time=$(date +%s)
    export PGPASSWORD="$POSTGRES_PASSWORD"
    until pg_isready -h postgres -p 5432 -U "$POSTGRES_USER" -d "$POSTGRES_DB"; do
        current_time=$(date +%s)
        if [ $((current_time - start_time)) -ge $timeout ]; then
            log "ERROR: PostgreSQL not ready after $timeout seconds"
            exit 1
        fi
        log "PostgreSQL not ready, retrying in 2 seconds..."
        sleep 2
    done
    log "PostgreSQL is ready"

    # Delay to ensure init-db.sh completes
    log "Waiting 10 seconds for database initialization..."
    sleep 10

    # Verify cedrina_dev role
    log "Verifying cedrina_dev role..."
    if ! psql -h postgres -p 5432 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT 1 FROM pg_roles WHERE rolname='cedrina_dev'" | grep -q "1"; then
        log "ERROR: cedrina_dev role does not exist"
        exit 1
    fi
    log "cedrina_dev role verified"

    # Wait for Redis
    log "Waiting for Redis at redis:$REDIS_PORT..."
    until redis-cli -h redis -p "$REDIS_PORT" ping >/dev/null 2>&1; do
        current_time=$(date +%s)
        if [ $((current_time - start_time)) -ge $timeout ]; then
            log "ERROR: Redis not ready after $timeout seconds"
            exit 1
        fi
        log "Redis not ready, retrying in 2 seconds..."
        sleep 2
    done
    log "Redis is ready"
else
    # Staging/Production: Check external services
    log "Checking external PostgreSQL at $POSTGRES_HOST:$POSTGRES_PORT..."
    retries=10
    attempt=1
    export PGPASSWORD="$POSTGRES_PASSWORD"
    while [ $attempt -le $retries ]; do
        if pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB"; then
            log "External PostgreSQL is ready"
            break
        fi
        log "PostgreSQL not ready (attempt $attempt/$retries), retrying in 5 seconds..."
        sleep 5
        attempt=$((attempt + 1))
    done
    if [ $attempt -gt $retries ]; then
        log "ERROR: Failed to connect to external PostgreSQL after $retries attempts"
        exit 1
    fi

    log "Checking external Redis at $REDIS_HOST:$REDIS_PORT..."
    redis_cmd="redis-cli -h $REDIS_HOST -p $REDIS_PORT"
    if [ -n "$REDIS_PASSWORD" ]; then
        redis_cmd="$redis_cmd -a $REDIS_PASSWORD"
    fi
    if [ "$REDIS_SSL" = "true" ]; then
        redis_cmd="$redis_cmd --tls"
    fi
    attempt=1
    while [ $attempt -le $retries ]; do
        if $redis_cmd ping >/dev/null 2>&1; then
            log "External Redis is ready"
            break
        fi
        log "Redis not ready (attempt $attempt/$retries), retrying in 5 seconds..."
        sleep 5
        attempt=$((attempt + 1))
    done
    if [ $attempt -gt $retries ]; then
        log "ERROR: Failed to connect to external Redis after $retries attempts"
        exit 1
    fi
fi

# Apply database migrations with retries
log "Applying database migrations..."
retries=3
attempt=1
while [ $attempt -le $retries ]; do
    if alembic upgrade head 2>&1 | tee /tmp/migration.log; then
        log "Database migrations applied successfully"
        break
    else
        log "Migration attempt $attempt/$retries failed. Error details:"
        cat /tmp/migration.log
        if [ $attempt -eq $retries ]; then
            log "ERROR: Database migration failed after $retries attempts"
            exit 1
        fi
        log "Retrying migration in 5 seconds..."
        sleep 5
        attempt=$((attempt + 1))
    fi
done

# Start the application
if [ "$APP_ENV" = "development" ]; then
    # Check if custom command was provided
    if [ $# -gt 0 ]; then
        log "Executing custom command: $*"
        exec "$@"
    else
        log "Starting Uvicorn with hot reload..."
        exec uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload --reload-dir /app/src
    fi
else
    # Check if custom command was provided
    if [ $# -gt 0 ]; then
        log "Executing custom command: $*"
        exec "$@"
    else
        log "Starting Gunicorn with Uvicorn workers..."
        exec gunicorn \
            -w "${GUNICORN_WORKERS:-$(nproc)}" \
            -k uvicorn.workers.UvicornWorker \
            --timeout "${GUNICORN_TIMEOUT:-120}" \
            --log-level "${GUNICORN_LOG_LEVEL:-info}" \
            --bind 0.0.0.0:8000 \
            src.main:app
    fi
fi