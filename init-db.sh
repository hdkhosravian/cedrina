#!/bin/bash
set -e

# Log script execution with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Initializing PostgreSQL database and role..."

# Source .env if it exists, with fallback defaults
ENV_FILE="/app/.env"
if [ -f "$ENV_FILE" ]; then
    log "Sourcing environment variables from $ENV_FILE..."
    set -a
    # shellcheck disable=SC1091
    . "$ENV_FILE"
    set +a
else
    log "WARNING: $ENV_FILE not found, using default values"
    export POSTGRES_USER=${POSTGRES_USER:-postgres}
    export POSTGRES_DB=${POSTGRES_DB:-cedrina_dev}
    export POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-postgres}
fi

# Validate required variables
if [ -z "$POSTGRES_USER" ] || [ -z "$POSTGRES_DB" ] || [ -z "$POSTGRES_PASSWORD" ]; then
    log "ERROR: POSTGRES_USER, POSTGRES_DB, or POSTGRES_PASSWORD not set"
    exit 1
fi

# Create the cedrina_dev database if it doesn't exist
log "Creating database $POSTGRES_DB if it doesn't exist..."
export PGPASSWORD="$POSTGRES_PASSWORD"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" <<-EOSQL
    DO
    \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_database WHERE datname = '$POSTGRES_DB') THEN
            CREATE DATABASE $POSTGRES_DB;
            RAISE NOTICE 'Database $POSTGRES_DB created';
        ELSE
            RAISE NOTICE 'Database $POSTGRES_DB already exists';
        END IF;
    END
    \$\$;
EOSQL
if [ $? -eq 0 ]; then
    log "Database creation check complete"
else
    log "ERROR: Failed to create or verify database $POSTGRES_DB"
    exit 1
fi

# Create the cedrina_dev role and configure database
log "Creating cedrina_dev role and configuring database..."
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO
    \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cedrina_dev') THEN
            CREATE ROLE cedrina_dev LOGIN PASSWORD 'cedrina_dev';
            RAISE NOTICE 'Role cedrina_dev created';
        ELSE
            RAISE NOTICE 'Role cedrina_dev already exists';
        END IF;
    END
    \$\$;
    GRANT ALL PRIVILEGES ON DATABASE $POSTGRES_DB TO cedrina_dev;
    ALTER DATABASE $POSTGRES_DB OWNER TO cedrina_dev;
    CREATE EXTENSION IF NOT EXISTS pgcrypto;
EOSQL
if [ $? -eq 0 ]; then
    log "Role creation and pgcrypto setup complete"
else
    log "ERROR: Failed to create role or enable pgcrypto"
    exit 1
fi

log "PostgreSQL initialization complete"