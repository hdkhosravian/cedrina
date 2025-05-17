#!/bin/sh
set -e

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Validate required environment variables
log "Validating environment variables..."
for var in SECRET_KEY DATABASE_URL REDIS_URL; do
    if [ -z "$(eval echo \$$var)" ]; then
        log "ERROR: $var is not set"
        exit 1
    fi
done

# Wait for services based on APP_ENV
if [ "$APP_ENV" = "development" ]; then
    # Wait for PostgreSQL
    log "Waiting for PostgreSQL at postgres:5432..."
    timeout=30
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
    # Staging/Production: Check external services with longer timeout
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

# Apply database migrations
log "Applying database migrations..."
export PGPASSWORD="$POSTGRES_PASSWORD"
alembic upgrade head || {
    log "ERROR: Database migration failed"
    exit 1
}

# Start the application
if [ "$APP_ENV" = "development" ]; then
    log "Starting Uvicorn with hot reload..."
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