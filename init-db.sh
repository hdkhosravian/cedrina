#!/bin/bash
set -e

# Log script execution
echo "Initializing PostgreSQL database and role..."

# Source .env.development if it exists, with fallback defaults
ENV_FILE="/app/.env.development"
if [ -f "$ENV_FILE" ]; then
    echo "Sourcing environment variables from $ENV_FILE..."
    # Export variables, ignoring comments and empty lines
    set -a
    # shellcheck disable=SC1091
    . "$ENV_FILE"
    set +a
else
    echo "WARNING: $ENV_FILE not found, using default values"
    export POSTGRES_USER=${POSTGRES_USER:-postgres}
    export POSTGRES_DB=${POSTGRES_DB:-cedrina_dev}
    export POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-postgres}
fi

# Validate required variables
if [ -z "$POSTGRES_USER" ] || [ -z "$POSTGRES_DB" ] || [ -z "$POSTGRES_PASSWORD" ]; then
    echo "ERROR: POSTGRES_USER, POSTGRES_DB, or POSTGRES_PASSWORD not set"
    exit 1
fi

# Create the cedrina_dev role and configure database
echo "Creating cedrina_dev role and configuring database..."
export PGPASSWORD="$POSTGRES_PASSWORD"
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
EOSQL

# Check if psql command succeeded
if [ $? -eq 0 ]; then
    echo "PostgreSQL initialization complete"
else
    echo "ERROR: PostgreSQL initialization failed"
    exit 1
fi