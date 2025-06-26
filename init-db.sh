#!/bin/bash
set -e

# Log script execution with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Initializing PostgreSQL databases and role..."

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
    export POSTGRES_DB_TEST=${POSTGRES_DB_TEST:-cedrina_test}
fi

# Validate required variables
if [ -z "$POSTGRES_USER" ] || [ -z "$POSTGRES_DB" ] || [ -z "$POSTGRES_PASSWORD" ] || [ -z "$POSTGRES_DB_TEST" ]; then
    log "ERROR: POSTGRES_USER, POSTGRES_DB, POSTGRES_PASSWORD, or POSTGRES_DB_TEST not set"
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
    log "Database $POSTGRES_DB creation check complete"
else
    log "ERROR: Failed to create or verify database $POSTGRES_DB"
    exit 1
fi

# Create the cedrina_test database if it doesn't exist
log "Creating test database $POSTGRES_DB_TEST if it doesn't exist..."
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" <<-EOSQL
    DO
    \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_database WHERE datname = '$POSTGRES_DB_TEST') THEN
            CREATE DATABASE $POSTGRES_DB_TEST;
            RAISE NOTICE 'Database $POSTGRES_DB_TEST created';
        ELSE
            RAISE NOTICE 'Database $POSTGRES_DB_TEST already exists';
        END IF;
    END
    \$\$;
EOSQL
if [ $? -eq 0 ]; then
    log "Database $POSTGRES_DB_TEST creation check complete"
else
    log "ERROR: Failed to create or verify database $POSTGRES_DB_TEST"
    exit 1
fi

# Create the cedrina_dev role and configure both databases
log "Creating cedrina_dev role and configuring databases..."
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
    log "Role creation and pgcrypto setup complete for $POSTGRES_DB"
else
    log "ERROR: Failed to create role or enable pgcrypto for $POSTGRES_DB"
    exit 1
fi

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB_TEST" <<-EOSQL
    GRANT ALL PRIVILEGES ON DATABASE $POSTGRES_DB_TEST TO cedrina_dev;
    ALTER DATABASE $POSTGRES_DB_TEST OWNER TO cedrina_dev;
    CREATE EXTENSION IF NOT EXISTS pgcrypto;
EOSQL
if [ $? -eq 0 ]; then
    log "Role configuration and pgcrypto setup complete for $POSTGRES_DB_TEST"
else
    log "ERROR: Failed to configure role or enable pgcrypto for $POSTGRES_DB_TEST"
    exit 1
fi

log "PostgreSQL initialization complete"