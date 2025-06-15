# Environment Settings Documentation for Cedrina (Development)

## Overview
This document provides a detailed explanation of the environment variables used in the `cedrina` project for the development environment. These settings are typically defined in the `.env` or `.env.development` file and are crucial for configuring the application's behavior, security, database connections, and more. The variables are categorized for clarity.

## Project Metadata
These variables provide basic information about the project and its environment.

- **PROJECT_NAME**: `cedrina`
  - The name of the project, used for identification and branding purposes.
- **VERSION**: `0.1.0`
  - The version of the application, useful for tracking releases and compatibility.
- **APP_ENV**: `development`
  - The environment in which the application is running. Possible values include `development`, `staging`, and `production`.
- **DEBUG**: `true`
  - Enables debug mode for detailed logging and error messages. Set to `true` for development to aid in troubleshooting.

## API Settings
These variables configure the API server's hosting and performance settings.

- **API_HOST**: `0.0.0.0`
  - The host IP address for the API server to bind to. `0.0.0.0` allows the server to accept connections from any network interface.
- **API_PORT**: `8000`
  - The port on which the API server will listen for incoming requests.
- **API_WORKERS**: `1`
  - Number of worker processes for handling API requests. Set to a minimum of 1 for development; increase for production based on server capacity.
- **RELOAD**: `true`
  - Enables auto-reload of the server on code changes. Useful for development but should be disabled in production.

## Logging
These settings control the application's logging behavior.

- **LOG_LEVEL**: `DEBUG`
  - The logging level for the application. Options are `DEBUG`, `INFO`, `WARNING`, `ERROR`, and `CRITICAL`. `DEBUG` provides the most detailed output, suitable for development.
- **LOG_JSON**: `true`
  - Determines whether logs are output in JSON format for structured logging. Set to `true` for easier log parsing and analysis.

## Security
These variables are critical for securing the application and its communications.

- **SECRET_KEY**: `6WhM3IaAWk456o802VHKpum2MB7zbD/h`
  - A secret key for cryptographic operations. Must be at least 32 characters long and should be kept secure. Replace with a unique, secure value in production.
- **ALLOWED_ORIGINS**: `http://0.0.0.0:8000,http://localhost:8000,http://127.0.0.1:8000`
  - Comma-separated list of allowed origins for CORS (Cross-Origin Resource Sharing). Configures which domains can access the API.

## pgcrypto
Settings for PostgreSQL's `pgcrypto` extension used for encryption.

- **PGCRYPTO_KEY**: `G2R7oPVxniZpDPrOUM7d4pVHDioUtSRj`
  - Key used by the `pgcrypto` extension in PostgreSQL for encrypting sensitive data like OAuth tokens. Ensure this is a secure, unique value and matches across environments.

## JWT (JSON Web Token) Settings
These variables configure JWT for authentication and authorization.

- **JWT_PUBLIC_KEY**: (truncated for brevity, begins with `-----BEGIN PUBLIC KEY-----`)
  - Public key for verifying JWT signatures. Used to validate incoming tokens.
- **JWT_PRIVATE_KEY**: (truncated for brevity, begins with `-----BEGIN PRIVATE KEY-----`)
  - Private key for signing JWTs. Must be kept secure and not exposed in public documentation or repositories.
- **JWT_ISSUER**: `https://api.example.com`
  - The issuer identifier for JWTs, typically a URL representing the token issuer.
- **JWT_AUDIENCE**: `cedrina:api:v1`
  - The intended audience for JWTs, used during token validation to ensure tokens are meant for this API.
- **ACCESS_TOKEN_EXPIRE_MINUTES**: `15`
  - Expiration time for access tokens in minutes. Short expiration enhances security by requiring frequent token refresh.
- **REFRESH_TOKEN_EXPIRE_DAYS**: `7`
  - Expiration time for refresh tokens in days. Longer duration allows users to stay authenticated without frequent logins.

## OAuth Settings for External Authentication Providers
These settings configure OAuth integration for external authentication providers. Values are placeholders and should be replaced with actual credentials from provider developer consoles.

- **GOOGLE_CLIENT_ID**: `""`
  - Client ID for Google OAuth authentication. Obtain from Google Developer Console.
- **GOOGLE_CLIENT_SECRET**: `""`
  - Client Secret for Google OAuth authentication. Must be kept secure.
- **MICROSOFT_CLIENT_ID**: `""`
  - Client ID for Microsoft OAuth authentication. Obtain from Azure Portal.
- **MICROSOFT_CLIENT_SECRET**: `""`
  - Client Secret for Microsoft OAuth authentication. Must be kept secure.
- **FACEBOOK_CLIENT_ID**: `""`
  - Client ID for Facebook OAuth authentication. Obtain from Facebook Developer Portal.
- **FACEBOOK_CLIENT_SECRET**: `""`
  - Client Secret for Facebook OAuth authentication. Must be kept secure.

## Database Settings for PostgreSQL
These variables configure the connection to the PostgreSQL database.

- **POSTGRES_USER**: `postgres`
  - Username for PostgreSQL database connection.
- **POSTGRES_PASSWORD**: `postgres`
  - Password for PostgreSQL database connection. Replace with a secure password in production.
- **POSTGRES_DB**: `cedrina_dev`
  - Name of the primary database for the application in development.
- **POSTGRES_DB_TEST**: `cedrina_test`
  - Name of the test database used for running tests.
- **POSTGRES_HOST**: `localhost`
  - Host address for the PostgreSQL server. Use `localhost` for local development or the container name in Docker setups.
- **POSTGRES_PORT**: `5432`
  - Port on which the PostgreSQL server is running.
- **POSTGRES_SSL_MODE**: `disable`
  - SSL mode for PostgreSQL connection. Options include `disable`, `allow`, `prefer`, `require`, `verify-ca`, and `verify-full`. Use `disable` for local development only.
- **POSTGRES_POOL_SIZE**: `5`
  - Maximum number of connections in the database pool.
- **POSTGRES_MAX_OVERFLOW**: `10`
  - Maximum number of connections to create beyond pool size during peak load.
- **POSTGRES_POOL_TIMEOUT**: `30`
  - Timeout in seconds for getting a connection from the pool.
- **DATABASE_URL**: `postgresql+psycopg2://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}?sslmode=${POSTGRES_SSL_MODE}`
  - Full connection URL for the database, constructed from other `POSTGRES_*` variables if not explicitly set.

## Redis Settings for Caching and Rate Limiting
These variables configure Redis for caching and rate limiting functionalities.

- **REDIS_HOST**: `redis`
  - Host address for the Redis server. Use the container name `redis` in Docker setups or the actual host in external configurations.
- **REDIS_PORT**: `6379`
  - Port on which the Redis server is running.
- **REDIS_PASSWORD**: `""`
  - Password for Redis server connection. Required for staging/production; keep secure.
- **REDIS_SSL**: `false`
  - Whether to use SSL for Redis connection. Set to `true` for secure environments.
- **REDIS_URL**: `redis://:${REDIS_PASSWORD}@${REDIS_HOST}:${REDIS_PORT}/0`
  - Full connection URL for Redis, constructed from other `REDIS_*` variables if not explicitly set.
- **RATE_LIMIT_ENABLED**: `true`
  - Enables rate limiting functionality to prevent abuse and ensure fair usage.
- **RATE_LIMIT_DEFAULT**: `100/minute`
  - Default rate limit rule, allowing 100 requests per minute per client.
- **RATE_LIMIT_STORAGE_URL**: `""`
  - Custom storage URL for rate limiting. Defaults to `REDIS_URL` if not set.
- **RATE_LIMIT_STRATEGY**: `fixed-window`
  - Strategy for rate limiting. Options include `fixed-window`, `sliding-window`, and `token-bucket`.
- **RATE_LIMIT_BLOCK_DURATION**: `60`
  - Duration in seconds to block a client after exceeding the rate limit.

## Language Settings
These settings configure internationalization (i18n) for the application.

- **SUPPORTED_LANGUAGES**: `["en", "fa", "ar"]`
  - Comma-separated list of supported languages for internationalization.
- **DEFAULT_LANGUAGE**: `en`
  - Default language to use if user preference is not specified.

## Additional Variables
Miscellaneous settings that may be used for specific purposes.

- **CEDRINA_DEV_PASSWORD**: `""`
  - Development password for Cedrina. Purpose not specified in code but mentioned in README. Replace with a secure value if used.

## Usage Notes
- **Security**: Sensitive values like `SECRET_KEY`, `JWT_PRIVATE_KEY`, `PGCRYPTO_KEY`, database passwords, and OAuth secrets must be kept secure and not committed to version control. Use environment-specific files (e.g., `.env.development`, `.env.production`) to manage these.
- **Environment-Specific Configurations**: Adjust values based on the environment. For instance, disable `DEBUG` and `RELOAD` in production, increase `API_WORKERS`, and enable `REDIS_SSL` and appropriate `POSTGRES_SSL_MODE`.
- **Dynamic URLs**: Variables like `DATABASE_URL` and `REDIS_URL` are constructed from other settings if not explicitly defined. Ensure component variables are correct to avoid connection issues.

## How to Configure
1. Copy the `.env.development` template to `.env` for local development or create environment-specific files (`.env.staging`, `.env.production`).
2. Update the values as per your setup, ensuring secure keys and credentials are used.
3. Use a tool like `python-dotenv` (already configured in `pytest.ini`) to load these variables into your application.

This documentation ensures that developers can understand and configure the `cedrina` project's environment settings for development, with considerations for security and scalability in other environments. 