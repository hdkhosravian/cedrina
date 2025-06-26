# Application Settings Configuration Documentation for Cedrina

## Overview
The `cedrina` project uses a structured approach to manage application settings through Python modules located in the `src/core/config/` directory. These settings are loaded from environment variables and `.env` files, validated using Pydantic, and aggregated into a single accessible configuration object. This document explains the purpose of each settings file, their contents, and how to customize them for different environments or requirements.

## Application Settings Configuration Files

### 1. `src/core/config/app.py`
- **What It Is**: A Python module defining application-wide settings.
- **What It Does**: Configures general application parameters such as project metadata, API server settings, logging, and CORS origins using Pydantic's `BaseSettings` for validation.
- **Key Contents**: 
  - `AppSettings` class with fields like `PROJECT_NAME` (default: "cedrina"), `VERSION` (default: "0.1.0"), `APP_ENV` (default: "development"), `DEBUG` (default: `False`), API settings (`API_HOST`, `API_PORT`, `API_WORKERS`), logging (`LOG_LEVEL`, `LOG_JSON`), security (`SECRET_KEY`), and language settings (`SUPPORTED_LANGUAGES`, `DEFAULT_LANGUAGE`).
  - Includes a validator for `ALLOWED_ORIGINS` to convert comma-separated strings into a list.
- **Location**: `src/core/config/app.py`
- **How to Customize**: 
  1. Override default values by setting environment variables in the appropriate `.env` file (e.g., `PROJECT_NAME=MyApp` in `.env.development`).
  2. Extend the `AppSettings` class in a custom module to add new fields or validators if the project requires additional application-wide settings.
  3. Modify validation logic (e.g., for `ALLOWED_ORIGINS`) to enforce stricter rules or different formats.
- **Important Notes**: Changes to defaults in code should be minimal; prefer environment variables for customization to maintain flexibility across environments. Ensure `SECRET_KEY` and other sensitive fields are sourced securely from environment variables.

### 2. `src/core/config/auth.py`
- **What It Is**: A Python module defining authentication and authorization settings.
- **What It Does**: Configures settings for OAuth providers and JWT (JSON Web Token) handling, including key loading from environment variables or PEM files.
- **Key Contents**: 
  - `AuthSettings` class with fields for OAuth provider credentials (`GOOGLE_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, etc.) and JWT settings (`JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`, `JWT_ISSUER`, `ACCESS_TOKEN_EXPIRE_MINUTES`, etc.).
  - Includes a model validator to load JWT keys from `.pem` files (`private.pem`, `public.pem`) if available, overriding environment variables.
- **Location**: `src/core/config/auth.py`
- **How to Customize**: 
  1. Set OAuth credentials and JWT keys via environment variables in `.env` files for security.
  2. Place `private.pem` and `public.pem` files in the project root to load JWT keys automatically, overriding environment settings.
  3. Adjust token expiration times (`ACCESS_TOKEN_EXPIRE_MINUTES`, `REFRESH_TOKEN_EXPIRE_DAYS`) based on security policies.
  4. Extend the class to support additional OAuth providers by adding new fields and validation logic.
- **Important Notes**: Never hardcode sensitive data like client secrets or private keys in code. Use secure storage (environment variables or files excluded from Git) and ensure proper logging to avoid leaking secrets in logs.

### 3. `src/core/config/database.py`
- **What It Is**: A Python module defining database connection settings.
- **What It Does**: Configures parameters for connecting to the PostgreSQL database, including credentials, host, port, and connection pool settings.
- **Key Contents**: 
  - `DatabaseSettings` class with fields like `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `POSTGRES_HOST`, `POSTGRES_PORT`, SSL mode (`POSTGRES_SSL_MODE`), pool settings (`POSTGRES_POOL_SIZE`, `POSTGRES_MAX_OVERFLOW`), and `PGCRYPTO_KEY` for encryption.
  - Includes a validator for `DATABASE_URL` to assemble the connection string if not explicitly provided.
- **Location**: `src/core/config/database.py`
- **How to Customize**: 
  1. Set database connection details via environment variables in `.env` files to match your environment (e.g., `POSTGRES_HOST=db.example.com` for production).
  2. Adjust pool settings (`POSTGRES_POOL_SIZE`, `POSTGRES_MAX_OVERFLOW`) based on expected load and server capacity.
  3. Modify `POSTGRES_SSL_MODE` to enforce secure connections in production (e.g., `require` or `verify-full`).
- **Important Notes**: Protect sensitive fields like `POSTGRES_PASSWORD` and `PGCRYPTO_KEY` using secure environment variables. Test connection settings in a non-production environment to avoid downtime.

### 4. `src/core/config/redis.py`
- **What It Is**: A Python module defining Redis connection and rate limiting settings.
- **What It Does**: Configures Redis for caching and rate limiting, ensuring secure and efficient connections with validation for different environments.
- **Key Contents**: 
  - `RedisSettings` class with fields like `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `REDIS_SSL`, and rate limiting settings (`RATE_LIMIT_ENABLED`, `RATE_LIMIT_DEFAULT`, `RATE_LIMIT_STRATEGY`).
  - Includes validators for `REDIS_URL` and `RATE_LIMIT_STORAGE_URL` to assemble connection strings, and for `REDIS_PASSWORD` to enforce its presence in staging/production.
- **Location**: `src/core/config/redis.py`
- **How to Customize**: 
  1. Set Redis connection details via environment variables to match your setup (e.g., `REDIS_HOST=redis.example.com`).
  2. Enable or disable rate limiting with `RATE_LIMIT_ENABLED` and adjust rules (`RATE_LIMIT_DEFAULT`, `RATE_LIMIT_STRATEGY`) based on API usage policies.
  3. Enforce SSL with `REDIS_SSL=true` for secure environments.
- **Important Notes**: Ensure `REDIS_PASSWORD` is set for staging and production as enforced by validation. Test rate limiting configurations to balance security and usability.

### 5. `src/core/config/settings.py`
- **What It Is**: The main settings module that aggregates all configuration classes into a single object.
- **What It Does**: Combines settings from `app.py`, `auth.py`, `database.py`, and `redis.py` into a unified `Settings` class, providing a single point of access for all application configurations.
- **Key Contents**: 
  - `Settings` class inheriting from `AppSettings`, `DatabaseSettings`, `RedisSettings`, and `AuthSettings`.
  - Configures Pydantic to load settings from `.env` files with `case_sensitive=True`.
  - Creates a singleton instance `settings = Settings()` for use throughout the application.
- **Location**: `src/core/config/settings.py`
- **How to Customize**: 
  1. Rarely needs direct customization; instead, customize individual modules (`app.py`, `database.py`, etc.) or environment variables.
  2. If additional settings categories are needed, create new modules and inherit them in the `Settings` class.
  3. Adjust `model_config` to change environment file loading behavior (e.g., different file encoding or extra field handling).
- **Important Notes**: This file acts as the central hub for settings. Avoid hardcoding values here; rely on environment variables or module defaults for flexibility.

## Customization Guidelines
- **Environment Variables First**: Prefer setting values via environment variables in `.env` files over changing defaults in code to maintain portability across environments (development, staging, production).
- **Security**: Protect sensitive data (e.g., `JWT_PRIVATE_KEY`, `POSTGRES_PASSWORD`) by using environment variables or secure file loading (like PEM files for keys). Avoid logging sensitive fields.
- **Validation**: Leverage Pydantic validators to enforce constraints (e.g., minimum length for keys, valid port ranges) and ensure settings are correct at startup.
- **Version Control**: Commit these configuration modules to Git as they define the structure of settings, but exclude any files or variables with sensitive data.
- **Testing Changes**: Test custom settings in a local environment by loading modified `.env` files or overriding variables to confirm application behavior before deploying to production.

## How to Use
1. Ensure the appropriate `.env` file (e.g., `.env.development`) is loaded to provide values for settings defined in these modules.
2. Access settings anywhere in the application via the singleton `settings` object (e.g., `from src.core.config.settings import settings; print(settings.PROJECT_NAME)`).
3. Override settings for testing or specific environments by setting environment variables or using different `.env` files (e.g., `APP_ENV=staging`).
4. Debug settings issues by checking logs for Pydantic validation errors or misconfigured values at application startup.

This documentation provides a clear understanding of application settings configuration in the `cedrina` project, enabling developers to manage and customize settings effectively across different environments. 