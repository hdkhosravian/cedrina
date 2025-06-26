# Environment Files Documentation for Cedrina

## Overview
Environment files in the `cedrina` project are used to define settings and configurations through key-value pairs of environment variables. These files are essential for customizing the application's behavior across different environments such as development, staging, and production. This document explains the purpose of each environment file, their contents, and how to customize them.

## Environment Files

### 1. `.env`
- **What It Is**: The default environment file, often a copy of `.env.development`, used for local setups.
- **What It Does**: Loaded by tools like `python-dotenv` to set environment variables for the application when no specific environment file is specified.
- **Key Contents**: Mirrors the structure of other environment-specific files, typically containing settings for project metadata, API configuration, security, database connections, Redis, and more.
- **Location**: Project root directory.
- **How to Customize**: 
  1. Copy `.env.development` to `.env` for local development if not already done.
  2. Adjust values to match your local setup or specific needs, ensuring sensitive data like passwords and keys are secure.
  3. Use this file for temporary or local overrides without modifying environment-specific files.
- **Important Notes**: Do not commit `.env` to version control. It should be excluded via `.gitignore` to prevent accidental exposure of sensitive data.

### 2. `.env.development`
- **What It Is**: Environment file tailored for local development.
- **What It Does**: Configures settings with debug mode enabled, local database and Redis connections, and less strict security settings suitable for development.
- **Key Contents**: Includes variables like `DEBUG=true`, `API_HOST=0.0.0.0`, `API_PORT=8000`, local database settings (`POSTGRES_HOST=localhost`), and default security keys.
- **Location**: Project root directory.
- **How to Customize**: 
  1. Modify values to match your local development environment, such as changing database credentials or API port if conflicts exist.
  2. Enable or disable features like `RELOAD=true` for auto-reload during development.
- **Important Notes**: This file is meant for development only. Settings like `DEBUG=true` should not be used in production due to security and performance concerns.

### 3. `.env.staging`
- **What It Is**: Environment file for staging environments.
- **What It Does**: Configures settings for a near-production setup, often pointing to external database and Redis servers with SSL enabled for testing.
- **Key Contents**: Similar to production but may retain some debug or logging features. Includes external service URLs, SSL settings (`POSTGRES_SSL_MODE=prefer` or `require`), and secure keys.
- **Location**: Project root directory.
- **How to Customize**: 
  1. Update database and Redis connection strings to point to staging servers.
  2. Adjust security settings and worker counts (`API_WORKERS`) to simulate production load while maintaining some debugging capabilities if needed.
- **Important Notes**: Ensure sensitive data is secure and consider using secret management tools for staging credentials. This file should also be excluded from version control.

### 4. `.env.production`
- **What It Is**: Environment file optimized for production environments.
- **What It Does**: Configures settings for secure, high-performance operation with external services, higher worker counts, and disabled debug features.
- **Key Contents**: Includes production-grade settings like `DEBUG=false`, `RELOAD=false`, external database/Redis URLs, `POSTGRES_SSL_MODE=require`, and optimized `API_WORKERS`.
- **Location**: Project root directory.
- **How to Customize**: 
  1. Set secure, unique values for all keys and credentials (`SECRET_KEY`, `JWT_PRIVATE_KEY`, etc.).
  2. Configure connection strings for production databases and caches.
  3. Optimize performance settings like `API_WORKERS` based on server capacity.
- **Important Notes**: Never commit this file to version control. Use secure secret management (e.g., HashiCorp Vault, AWS Secrets Manager) for production credentials.

## Detailed Variable Documentation
For a comprehensive list and explanation of all environment variables defined in these files (e.g., `PROJECT_NAME`, `DATABASE_URL`, `JWT_PUBLIC_KEY`), refer to `docs/environment_settings.md`. This document provides detailed descriptions, default values for development, and usage notes for each variable.

## Customization Guidelines
- **Environment-Specific Settings**: Tailor each file to its intended environment. For example, disable `DEBUG` and `RELOAD` in `.env.production`, and ensure `POSTGRES_SSL_MODE` is set to a secure value like `require`.
- **Security**: Sensitive data such as `SECRET_KEY`, database passwords, and OAuth secrets must not be hardcoded or committed to Git. Use `.gitignore` to exclude these files.
- **Loading Mechanism**: Ensure the application or test scripts load the correct environment file. The `cedrina` project uses `python-dotenv` (configured in `pytest.ini` for tests) to load variables from the appropriate `.env` file.
- **Testing Customizations**: Test changes to environment files in a local or staging setup before applying to production to avoid connection issues or security risks.

## How to Use
1. Choose the appropriate environment file based on your deployment context (e.g., `.env.development` for local work).
2. Copy it to `.env` if working locally, or specify the file explicitly in deployment scripts (e.g., `dotenv -e .env.staging`).
3. Update values as needed, following security best practices.
4. Verify the application loads the correct settings by checking logs or environment variable values at runtime.

This documentation ensures developers can effectively manage and customize environment configurations for the `cedrina` project across various deployment scenarios. 