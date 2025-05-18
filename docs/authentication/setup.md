# Authentication System Setup

## Overview
The Cedrina authentication system uses PostgreSQL to store user data, OAuth profiles, and sessions, defined in `src/domain/entities/`. Alembic manages database migrations, and the `pgcrypto` extension encrypts OAuth tokens. In Docker, migrations are applied automatically via `entrypoint.sh`, and `pgcrypto` is enabled by `init-db.sh`.

## Prerequisites
- **PostgreSQL 16**: Dockerized for development (`postgres` service) or external for staging/production.
- **Redis 7**: Dockerized for development (`redis` service) or external for staging/production.
- **Poetry 2.1.3**: For dependency management.
- **Docker**: For development and testing environments.
- **Environment Files**: `.env.development`, `.env.staging`, or `.env.production` with valid `DATABASE_URL`, `REDIS_URL`, and `PGCRYPTO_KEY`.

## Setup Steps

1. **Enable pgcrypto Extension**:
   - **Development**: Automatically enabled by `init-db.sh` in the `postgres` service (`docker-compose.yml`).
   - **Staging/Production**: Manually enable on external databases:
     ```bash
     psql -U postgres -h external.db.host -d cedrina_staging -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
     ```

2. **Configure pgcrypto Key**:
   - Add to `.env.*`:
     ```plaintext
     PGCRYPTO_KEY=your-pgcrypto-encryption-key-1234567890123456
     ```
   - Generate a secure key:
     ```bash
     openssl rand -base64 24
     ```

3. **Generate and Apply Migrations**:
   - **Local Development (Non-Docker)**:
     ```bash
     poetry run alembic revision --autogenerate -m "Add tables"
     make db-migrate
     ```
   - **Docker (Development/Production)**:
     Migrations are applied automatically when starting containers:
     - Development: `make run-dev`
     - Staging: `make run-staging`
     - Production: `make run-prod`
     Ensure `docker-compose.yml` does not override `entrypoint.sh` with `command`.

4. **Verify Database Schema**:
   - **Local**:
     ```bash
     psql -U postgres -d cedrina_dev -c "\dt"
     psql -U postgres -d cedrina_dev -c "\d+ users"
     ```
     If no output, use a `psql` session:
     ```bash
     psql -U postgres -d cedrina_dev
     \d+ users
     ```
   - **Docker**:
     ```bash
     docker exec cedrina_postgres_1 psql -U postgres -d cedrina_dev -c "\dt"
     docker exec cedrina_postgres_1 psql -U postgres -d cedrina_dev -c "\d+ users"
     ```
   - Verify `pgcrypto`:
     ```bash
     docker exec cedrina_postgres_1 psql -U postgres -d cedrina_dev -c "SELECT pgp_sym_encrypt('test_token', 'your-pgcrypto-encryption-key-1234567890123456') AS encrypted;"
     ```
     Replace `your-pgcrypto-encryption-key-1234567890123456` with the actual `PGCRYPTO_KEY` from `.env.development`. Alternatively, use:
     ```bash
     docker exec cedrina_postgres_1 bash -c "psql -U postgres -d cedrina_dev -c \"SELECT pgp_sym_encrypt('test_token', '$PGCRYPTO_KEY') AS encrypted;\""
     ```
   - Check migration revision:
     ```bash
     docker exec cedrina_postgres_1 psql -U postgres -d cedrina_dev -c "SELECT * FROM alembic_version;"
     ```

## Troubleshooting
- **No tables in Docker**:
  - Ensure `docker-compose.yml` does not override `entrypoint.sh`. Check logs:
    ```bash
    docker logs cedrina_app_1
    docker logs cedrina_postgres_1
    ```
  - Verify `init-db.sh` ran:
    ```bash
    docker logs cedrina_postgres_1
    ```
  - Clear volumes and retry:
    ```bash
    make clean
    make clean-volumes
    make run-dev
    ```
- **pgcrypto not enabled**:
  - Check `init-db.sh` logs for errors. Manually enable if needed:
    ```bash
    docker exec cedrina_postgres_1 psql -U postgres -d cedrina_dev -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
    ```
- **pgcrypto verification fails**:
  - Use the actual `PGCRYPTO_KEY` value instead of `$PGCRYPTO_KEY`:
    ```bash
    docker exec cedrina_postgres_1 psql -U postgres -d cedrina_dev -c "SELECT pgp_sym_encrypt('test_token', 'your-pgcrypto-encryption-key-1234567890123456') AS encrypted;"
    ```
  - Ensure `PGCRYPTO_KEY` is set in `.env.development`.
- **Container exits with code 0**:
  - Verify `entrypoint.sh` explicitly runs Uvicorn in development:
    ```bash
    docker logs cedrina_app_1
    ```

## Next Steps
- Implement authentication logic in `src/domain/services/` using `python-jose` for JWT and `authlib` for OAuth.
- Add API endpoints in `src/adapters/api/v1/`.
- Update this document with authentication logic details.