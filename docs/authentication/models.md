# Authentication Models

## Overview
In the Cedrina authentication system, **models** represent the core data structures that define the entities involved in user authentication, authorization, and session management. These models are implemented using [SQLModel](https://sqlmodel.tiangolo.com/), a Python library that combines SQLAlchemy’s ORM capabilities with Pydantic’s data validation, enabling seamless integration with PostgreSQL and FastAPI. Models are defined in the domain layer (`src/domain/entities/`), adhering to Domain-Driven Design (DDD) principles, where they encapsulate business logic, data integrity, and persistence rules.

The authentication system includes three primary models: `User`, `OAuthProfile`, and `Session`. These models map to database tables (`users`, `oauth_profiles`, `sessions`) and support features like username/password authentication, OAuth integration, JWT-based session management, and secure token encryption using PostgreSQL’s `pgcrypto` extension. Each model is designed to ensure data consistency, security, and performance, with constraints, indexes, and validation rules tailored to enterprise-grade requirements.

## What Are Models?
Models in Cedrina serve as blueprints for data entities, defining:

- **Structure**: The fields (attributes) of an entity, their data types, and relationships (e.g., foreign keys).
- **Validation**: Rules enforced by Pydantic to ensure data integrity (e.g., email format, username constraints).
- **Persistence**: Mapping to PostgreSQL tables via SQLModel, with SQLAlchemy handling database operations.
- **Business Logic**: Domain-specific rules, such as unique constraints, default values, and auditing timestamps.

In DDD, models are part of the **domain layer**, representing the core concepts of the authentication system. They are used in:

- **Database Migrations**: Alembic uses model definitions to generate table schemas (`alembic/versions/`).
- **API Endpoints**: FastAPI routes interact with models to create, read, update, or delete data.
- **Services**: Authentication logic (e.g., `AuthService`) manipulates model instances for login, OAuth, and token management.
- **Security**: Features like encrypted OAuth tokens (`pgcrypto`) and hashed passwords (`bcrypt`) are integrated into model fields.

SQLModel’s hybrid nature allows models to serve both as database schemas (via SQLAlchemy) and API data models (via Pydantic), reducing code duplication and ensuring type safety.

## Authentication Models

### User Model
**File**: `src/domain/entities/user.py`

**Purpose**: Represents a user in the authentication system, supporting both username/password and OAuth-based authentication. It stores core user information, roles for access control, and auditing timestamps.

**Table**: `users`

**Fields**:
- `id` (INTEGER, Primary Key): Unique identifier, auto-incremented.
- `username` (VARCHAR, Unique): User’s login name, 3-50 characters, alphanumeric with underscores/hyphens.
- `email` (VARCHAR, Unique): User’s email address, validated by Pydantic’s `EmailStr`.
- `hashed_password` (VARCHAR(255), Nullable): Bcrypt-hashed password, null for OAuth-only users.
- `role` (ENUM: 'admin', 'user'): Role for RBAC, defaults to `user`.
- `is_active` (BOOLEAN): Account status, defaults to `true`.
- `created_at` (TIMESTAMP): Creation timestamp, set by database (`CURRENT_TIMESTAMP`).
- `updated_at` (TIMESTAMP, Nullable): Last update timestamp, updated by database.

**Constraints and Indexes**:
- Unique constraints on `username` and `email`.
- Indexes on `lower(username)` and `lower(email)` for case-insensitive searches.
- Primary key on `id`.

**Usage**:
- Stores user credentials for login.
- Links to `OAuthProfile` and `Session` via foreign keys.
- Supports RBAC via `role`.

### OAuthProfile Model
**File**: `src/domain/entities/oauth_profile.py`

**Purpose**: Links users to OAuth provider accounts (e.g., Google, Microsoft, Facebook), storing provider-specific data and encrypted access tokens.

**Table**: `oauth_profiles`

**Fields**:
- `id` (INTEGER, Primary Key): Unique identifier, auto-incremented.
- `user_id` (INTEGER, Foreign Key): References `users.id`, links to a `User`.
- `provider` (ENUM: 'google', 'microsoft', 'facebook'): OAuth provider.
- `provider_user_id` (VARCHAR): Unique user ID from the provider.
- `access_token` (BYTEA): Encrypted OAuth access token, using `pgcrypto`.
- `expires_at` (TIMESTAMP): Token expiration timestamp.
- `created_at` (TIMESTAMP): Creation timestamp (`CURRENT_TIMESTAMP`).
- `updated_at` (TIMESTAMP, Nullable): Last update timestamp.

**Constraints and Indexes**:
- Foreign key constraint on `user_id` with `ON DELETE CASCADE`.
- Unique index on `provider` and `provider_user_id`.
- Index on `user_id` for efficient joins.

**Usage**:
- Stores OAuth credentials for third-party authentication.
- Encrypts `access_token` to secure API access.
- Links OAuth accounts to `User` records.

### Session Model
**File**: `src/domain/entities/session.py`

**Purpose**: Tracks JWT refresh tokens and session state for user authentication, supporting token rotation and revocation.

**Table**: `sessions`

**Fields**:
- `id` (INTEGER, Primary Key): Unique identifier, auto-incremented.
- `jti` (UUID, Unique): JWT ID for token revocation, generated as a UUID.
- `user_id` (INTEGER, Foreign Key): References `users.id`, links to a `User`.
- `refresh_token_hash` (VARCHAR(255)): Hashed refresh token for validation.
- `created_at` (TIMESTAMP): Creation timestamp (`CURRENT_TIMESTAMP`).
- `expires_at` (TIMESTAMP): Token expiration timestamp.
- `revoked_at` (TIMESTAMP, Nullable): Revocation timestamp, null if active.

**Constraints and Indexes**:
- Foreign key constraint on `user_id` with `ON DELETE CASCADE`.
- Unique constraint on `jti`.
- Indexes on `jti` and `(user_id, expires_at)` for efficient queries.

**Usage**:
- Manages refresh tokens for JWT-based authentication.
- Supports token revocation via `revoked_at`.
- Integrates with Redis for caching active sessions.

## Model Implementation Details
- **SQLModel**: Combines SQLAlchemy for database operations and Pydantic for validation. Models inherit from `SQLModel, table=True` to define tables.
- **Pydantic Validation**:
  - `User.email` uses `EmailStr` for format validation.
  - `User.username` has a custom validator for alphanumeric characters, underscores, and hyphens.
- **SQLAlchemy Features**:
  - Uses `sa_column=Column(...)` for precise database types (e.g., `DateTime`, `String`, `BYTEA`).
  - Defines enums (`Role`, `Provider`) as PostgreSQL `ENUM` types.
  - Implements indexes and constraints for performance and integrity.
- **pgcrypto Integration**:
  - `OAuthProfile.access_token` uses `BYTEA` with `pgcrypto` for encryption, requiring `PGCRYPTO_KEY` in `.env.*`.
- **Auditing**:
  - `created_at` and `updated_at` fields use database defaults (`CURRENT_TIMESTAMP`) for tracking changes.

## Usage in Authentication System
- **Migrations**: Alembic uses model metadata (`SQLModel.metadata`) in `alembic/env.py` to generate table schemas (`alembic/versions/`).
- **Authentication Logic**: Models are manipulated by `AuthService` (planned for `src/domain/services/`) for:
  - User creation/login (`User`).
  - OAuth token storage (`OAuthProfile`).
  - Session management (`Session`).
- **API Endpoints**: FastAPI routes (to be implemented in `src/adapters/api/v1/`) will use models for data validation and persistence.
- **Security**:
  - Passwords are hashed (`hashed_password`) using `bcrypt` via `passlib`.
  - OAuth tokens are encrypted (`access_token`) using `pgcrypto`.
  - JWT tokens are validated via `jti` in `Session`.

## Verification
To verify the models are correctly set up:

1. **Check Tables**:
   ```bash
   docker exec cedrina_postgres_1 psql -U postgres -d cedrina_dev -c "\dt"
   ```
   Expected output:
   ```
            List of relations
    Schema |      Name       | Type  |  Owner
   --------+-----------------+-------+----------
    public | alembic_version | table | postgres
    public | oauth_profiles  | table | postgres
    public | sessions        | table | postgres
    public | users           | table | postgres
   (4 rows)
   ```

2. **Inspect Schema**:
   ```bash
   docker exec cedrina_postgres_1 psql -U postgres -d cedrina_dev -c "\d+ users"
   ```

3. **Verify pgcrypto**:
   ```bash
   docker exec cedrina_postgres_1 psql -U postgres -d cedrina_dev -c "SELECT pgp_sym_encrypt('test_token', 'your-pgcrypto-encryption-key-1234567890123456') AS encrypted;"
   ```
   Replace `your-pgcrypto-encryption-key-1234567890123456` with the actual `PGCRYPTO_KEY` from `.env.development`. Alternatively:
   ```bash
   docker exec cedrina_postgres_1 bash -c "psql -U postgres -d cedrina_dev -c \"SELECT pgp_sym_encrypt('test_token', '$PGCRYPTO_KEY') AS encrypted;\""
   ```

4. **Test Application**:
   ```bash
   curl -f http://localhost:8000/api/v1/health
   ```

## Troubleshooting
- **pgcrypto Verification Fails**:
  - Ensure `PGCRYPTO_KEY` is set in `.env.development`.
  - Use the actual key value in commands:
    ```bash
    docker exec cedrina_postgres_1 psql -U postgres -d cedrina_dev -c "SELECT pgp_sym_encrypt('test_token', 'your-pgcrypto-encryption-key-1234567890123456') AS encrypted;"
    ```
  - Verify `pgcrypto` is enabled:
    ```bash
    docker exec cedrina_postgres_1 psql -U postgres -d cedrina_dev -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
    ```
- **Tables Missing**:
  - Check `entrypoint.sh` and `init-db.sh` logs:
    ```bash
    docker logs cedrina_app_1
    docker logs cedrina_postgres_1
    ```
  - Clear volumes and retry:
    ```bash
    make clean
    make clean-volumes
    make run-dev
    ```

## Next Steps
- Implement `AuthService` in `src/domain/services/` for authentication logic.
- Define API endpoints in `src/adapters/api/v1/`.
- Update this document with model usage in authentication workflows.