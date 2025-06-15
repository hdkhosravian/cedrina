# Configuration Files Overview for Cedrina

## Introduction
The `cedrina` project relies on various configuration files to manage environment settings, dependencies, database migrations, and application behavior across different environments (development, staging, production). This document provides a comprehensive overview of each configuration file, explaining what they are, what they do, and how developers can customize them to suit specific needs. Understanding and properly managing these files is crucial for setting up, running, and scaling the application.

## Directory Structure for Configuration
Configuration files are primarily located in the project root directory, with some specific configurations nested within subdirectories like `alembic/` for database migrations. Below, we detail each file or set of files relevant to configuration.

## Configuration Files and Their Roles

### 1. Environment Files (`.env`, `.env.development`, `.env.staging`, `.env.production`)
- **What They Are**: These are environment-specific configuration files that store key-value pairs of environment variables. They define settings for the application such as database connections, API host/port, security keys, and more.
- **What They Do**: 
  - `.env`: Acts as the default environment file, often a copy of `.env.development` for local setups. It is loaded by tools like `python-dotenv` to set environment variables for the application.
  - `.env.development`: Configures settings for local development with debug mode enabled, local database/Redis connections, and less strict security settings.
  - `.env.staging`: Tailored for a staging environment, often pointing to external database/Redis servers with SSL enabled for testing in a near-production setup.
  - `.env.production`: Optimized for production with secure settings, external services, higher worker counts, and disabled debug features.
- **Key Contents**: Includes variables for project metadata (`PROJECT_NAME`, `VERSION`), API settings (`API_HOST`, `API_PORT`), security (`SECRET_KEY`, `JWT_*`), database (`DATABASE_URL`, `POSTGRES_*`), Redis (`REDIS_URL`, `RATE_LIMIT_*`), and more. See `docs/environment_settings.md` for a detailed breakdown of variables.
- **How to Customize**: 
  1. Copy the appropriate template (e.g., `.env.development`) to `.env` for local use or create a new file for a custom environment.
  2. Modify values to match your setup, ensuring sensitive data like passwords and keys are secure and not committed to version control.
  3. Use environment-specific files to override settings for different deployments. For example, disable `DEBUG` and `RELOAD` in `.env.production`, and set `POSTGRES_SSL_MODE` to `require`.
  4. Ensure `pytest.ini` or application startup scripts load the correct file using `python-dotenv`.
- **Important Notes**: Never commit sensitive data in these files to Git. Use `.gitignore` to exclude them, and consider vault services or CI/CD secrets for production credentials.

### 2. Poetry Configuration (`pyproject.toml`, `poetry.lock`)
- **What They Are**: These files manage project dependencies and metadata using Poetry, a dependency and packaging manager for Python.
- **What They Do**: 
  - `pyproject.toml`: Defines project metadata (name, version, description), dependencies (e.g., FastAPI, SQLModel, Redis), development dependencies (e.g., pytest, black), and tool configurations (e.g., mypy, ruff for linting).
  - `poetry.lock`: Locks the exact versions of dependencies to ensure reproducibility across environments.
- **Key Contents**: 
  - Dependencies section lists runtime requirements like `fastapi`, `sqlmodel`, and `redis`.
  - Dev-dependencies include testing and formatting tools like `pytest`, `black`, and `isort`.
  - Tool settings configure static typing (`mypy`), linting (`ruff`), and formatting (`black`).
- **How to Customize**: 
  1. Add or update dependencies in `pyproject.toml` under `[tool.poetry.dependencies]` or `[tool.poetry.group.dev.dependencies]` using `poetry add <package>` for automatic updates.
  2. Modify tool settings (e.g., `mypy` strictness or `black` line length) under respective `[tool.*]` sections to align with project coding standards.
  3. Run `poetry update` to refresh `poetry.lock` after changes to `pyproject.toml`.
  4. Use `poetry config` to set global Poetry settings like virtual environment paths if needed.
- **Important Notes**: Commit both files to version control to ensure consistent dependency resolution. Avoid manual edits to `poetry.lock` as it's auto-generated.

### 3. Docker Configuration (`Dockerfile`, `docker-compose.yml`, `entrypoint.sh`)
- **What They Are**: These files configure the containerization of the `cedrina` application for development, testing, and deployment using Docker.
- **What They Do**: 
  - `Dockerfile`: Defines a multi-stage build process for the application, including stages for building dependencies (`builder`), precompiling assets (`precompiler`), and running the app (`runtime`).
  - `docker-compose.yml`: Configures services for development and testing, defining `api` (the FastAPI app), `postgres` (database), and `redis` (caching/rate limiting) with environment variables, volumes, and network settings.
  - `entrypoint.sh`: A shell script executed when the Docker container starts, handling tasks like database migrations and starting the server with Uvicorn.
- **Key Contents**: 
  - `Dockerfile`: Specifies Python version, installs Poetry, copies code, and sets up the runtime environment.
  - `docker-compose.yml`: Maps ports (e.g., `8000:8000` for API), sets environment files, defines persistent volumes for database data, and includes conditional profiles.
  - `entrypoint.sh`: Checks for migrations, applies them via Alembic, and starts the application server.
- **How to Customize**: 
  1. Modify `Dockerfile` to change Python versions, add system packages, or adjust build steps for specific requirements (e.g., additional libraries for machine learning).
  2. Update `docker-compose.yml` to add services (e.g., a message broker like RabbitMQ), change port mappings, or adjust resource limits (CPU, memory) for production-like testing.
  3. Extend `entrypoint.sh` to include custom startup tasks like data seeding or waiting for dependent services to be ready.
  4. Use environment-specific Compose files (e.g., `docker-compose.prod.yml`) with `docker-compose -f` for staging/production overrides.
- **Important Notes**: Ensure `docker-compose.yml` does not override `entrypoint.sh` with a custom `command` unless intentional. Test customizations locally before deploying to avoid breaking container startup.

### 4. Alembic Configuration (`alembic/env.py`, `alembic/script.py.mako`)
- **What They Are**: Configuration files for Alembic, the database migration tool used in `cedrina` to manage PostgreSQL schema changes.
- **What They Do**: 
  - `alembic/env.py`: Configures the migration environment, connecting to the database using `settings.DATABASE_URL` and defining the `target_metadata` for SQLModel to detect schema changes.
  - `alembic/script.py.mako`: A template file for generating migration scripts, defining revision metadata and placeholders for `upgrade()` and `downgrade()` functions.
- **Key Contents**: 
  - `env.py`: Sets up logging, retrieves database URL from settings, and configures Alembic context for migrations.
  - `script.py.mako`: Provides a structure for new migration scripts with placeholders for schema changes.
- **How to Customize**: 
  1. Modify `env.py` to adjust database connection logic or add custom migration behaviors (e.g., pre-migration checks or custom metadata handling).
  2. Update `script.py.mako` to change the default structure or comments in generated migration scripts for better readability or compliance with project standards.
  3. Use environment variables or conditional logic in `env.py` to handle different database URLs for development vs. production.
- **Important Notes**: Customizing these files requires understanding Alembic's internals. Test changes in a development environment first, as errors can prevent migrations from running. Always commit migration scripts in `alembic/versions/` to version control.

### 5. Pytest Configuration (`pytest.ini`)
- **What It Is**: A configuration file for Pytest, the testing framework used in `cedrina` for unit and integration tests.
- **What It Does**: Configures Pytest behavior, setting the Python path to `src` for proper module imports and enabling environment variable loading via `pytest-dotenv`.
- **Key Contents**: 
  - Sets `pythonpath = src` to ensure tests can import modules from the source directory.
  - Enables `dotenv` to load environment variables from `.env` files during testing.
- **How to Customize**: 
  1. Add Pytest markers or custom options under `[pytest]` to filter tests or change behaviors (e.g., `markers = slow: marks tests as slow`).
  2. Adjust `pythonpath` if the project structure changes or additional paths are needed.
  3. Specify a different `.env` file for tests by setting `env_files = .env.test` if test-specific configurations are required.
- **Important Notes**: Ensure `pytest.ini` is at the project root for Pytest to detect it automatically. Customizations should align with testing workflows to avoid breaking CI/CD pipelines.

### 6. Babel Configuration (`babel.cfg`)
- **What It Is**: A configuration file for Babel, a tool used in `cedrina` for internationalization (i18n) to extract translation keys from source code.
- **What It Does**: Defines how Babel scans the codebase for translatable strings, specifying file types and extraction rules.
- **Key Contents**: 
  - Configures file patterns (e.g., Python files) and keywords (e.g., `_`, `gettext`) to identify strings for translation.
- **How to Customize**: 
  1. Update file patterns or directories in `babel.cfg` to include additional file types (e.g., templates) or exclude irrelevant paths.
  2. Add custom keywords if the project uses non-standard functions for marking translatable strings.
  3. Adjust output settings for the translation template file (`messages.pot`) if needed.
- **Important Notes**: Customizations should be tested by running `pybabel extract` to ensure all translatable strings are captured without extraneous noise. Keep aligned with `locales/` directory structure.

### 7. Makefile
- **What It Is**: A build automation file that defines tasks for building, running, testing, and maintaining the `cedrina` project.
- **What It Does**: Provides shortcuts for common commands like starting the development server, running tests, formatting code, managing Docker containers, and applying migrations.
- **Key Contents**: 
  - Defines targets like `run-dev`, `test`, `lint`, `format`, `db-migrate`, `clean`, and Docker-related tasks.
- **How to Customize**: 
  1. Add new targets for project-specific tasks (e.g., `seed-data` for populating the database with test data).
  2. Modify existing commands to use different tools or parameters (e.g., change test coverage options).
  3. Include environment-specific targets (e.g., `run-staging` or `run-prod`) with appropriate environment files or Compose configurations.
- **Important Notes**: Ensure `Makefile` commands are compatible with both local and Docker workflows. Test custom targets locally to avoid breaking automated scripts or CI/CD processes.

## General Customization Guidelines
- **Environment Awareness**: Always consider the target environment (development, staging, production) when customizing configurations. Settings suitable for development (e.g., `DEBUG=true`) may pose security risks or performance issues in production.
- **Security First**: Protect sensitive data in configuration files. Use environment variables for secrets, avoid hardcoding credentials, and leverage secure storage solutions (e.g., HashiCorp Vault, AWS Secrets Manager) for production.
- **Version Control**: Commit non-sensitive configuration files (`pyproject.toml`, `poetry.lock`, `pytest.ini`, `babel.cfg`, `Makefile`) to Git for consistency across team members. Exclude `.env` files and sensitive data using `.gitignore`.
- **Testing Changes**: Test all customizations in a local or staging environment before applying them to production to prevent downtime or errors.
- **Documentation**: Update project documentation (like this file or README.md) when configurations are customized significantly, ensuring team members understand the changes and their implications.

## Conclusion
The configuration files in `cedrina` provide a robust framework for managing the application's behavior, dependencies, and deployment. By understanding and customizing these files appropriately, developers can tailor the project to specific requirements, ensure security, and maintain scalability. Refer to individual configuration files or related documentation (e.g., `environment_settings.md` for detailed `.env` variables) for deeper insights into specific settings. 