# Docker Configuration Documentation for Cedrina

## Overview
Docker is used in the `cedrina` project to containerize the application, making it easier to develop, test, and deploy across different environments. This document explains the purpose of Docker configuration files, their contents, and how to customize them to meet specific requirements.

## Docker Configuration Files

### 1. `Dockerfile`
- **What It Is**: A multi-stage build configuration file for creating the Docker image of the `cedrina` application.
- **What It Does**: Defines the build process with stages for building dependencies, precompiling assets, and setting up the runtime environment for the FastAPI application.
- **Key Contents**: 
  - **Builder Stage**: Installs Poetry, sets up the Python environment, and installs dependencies.
  - **Precompiler Stage**: Precompiles any assets or additional build steps if needed.
  - **Runtime Stage**: Copies the application code, sets environment variables, and configures the entry command to run the server.
- **Location**: Project root directory.
- **How to Customize**: 
  1. Change the Python version in the `FROM` statement to match project requirements (e.g., `FROM python:3.9-slim`).
  2. Add system packages or libraries in the builder stage if the application requires additional dependencies (e.g., `apt-get install -y gcc` for C extensions).
  3. Modify the runtime stage to include custom environment variables or commands (e.g., changing the default port or server command).
  4. Add health check instructions if needed for container monitoring.
- **Important Notes**: Test customizations locally with `docker build -t cedrina-test .` to ensure the image builds and runs correctly. Keep the image lightweight by minimizing installed packages in the runtime stage.

### 2. `docker-compose.yml`
- **What It Is**: A configuration file for Docker Compose, which orchestrates multiple containers for development and testing.
- **What It Does**: Defines services like `api` (the FastAPI app), `postgres` (database), and `redis` (caching/rate limiting), along with their configurations, networking, and dependencies.
- **Key Contents**: 
  - **api Service**: Configures the application container, mapping ports (e.g., `8000:8000`), setting environment files, and linking to database and Redis services.
  - **postgres Service**: Sets up the PostgreSQL database with environment variables, persistent volumes for data, and health checks.
  - **redis Service**: Configures Redis for caching and rate limiting, also with environment settings and volumes.
  - Includes conditional profiles or environment-specific settings.
- **Location**: Project root directory.
- **How to Customize**: 
  1. Add new services (e.g., a message broker like RabbitMQ) by defining them with appropriate images, ports, and dependencies.
  2. Change port mappings if conflicts occur (e.g., map `8080:8000` if port 8000 is in use).
  3. Adjust resource limits (CPU, memory) under each service for performance testing or production-like environments.
  4. Use environment-specific Compose files (e.g., `docker-compose.prod.yml`) with `docker-compose -f` for staging or production overrides.
- **Important Notes**: Ensure the `api` service does not override `entrypoint.sh` with a custom `command` unless intentional. Test Compose configurations with `docker-compose up` to verify service interactions.

### 3. `entrypoint.sh`
- **What It Is**: A shell script executed as the entrypoint when the Docker container starts.
- **What It Does**: Handles startup tasks such as running database migrations via Alembic and starting the application server with Uvicorn.
- **Key Contents**: 
  - Checks for database availability and applies migrations if needed.
  - Starts the FastAPI server with configurable options (e.g., host, port, workers).
- **Location**: Project root directory.
- **How to Customize**: 
  1. Add custom startup tasks like data seeding or waiting for dependent services (e.g., using `wait-for-it.sh` to delay until database is ready).
  2. Modify server startup options (e.g., change Uvicorn log level or worker count) based on environment variables.
  3. Include pre-start checks or logging to aid debugging in containerized environments.
- **Important Notes**: Ensure the script remains executable (`chmod +x entrypoint.sh`) and is correctly referenced in the `Dockerfile` or Compose file. Test changes by building and running the container to confirm startup behavior.

## Customization Guidelines
- **Environment Awareness**: Tailor Docker configurations based on the target environment. For development, prioritize ease of use (e.g., volume mounts for code changes); for production, focus on security and performance (e.g., minimal images, resource limits).
- **Security**: Avoid hardcoding sensitive data in `Dockerfile` or `docker-compose.yml`. Use environment files or secret management for credentials and keys.
- **Version Control**: Commit these configuration files to Git for consistency across deployments, but exclude environment-specific overrides or secrets.
- **Testing Changes**: Always test Docker customizations locally before deploying to staging or production. Use `docker logs` to debug container startup issues.

## How to Use
1. Build the Docker image with `docker build -t cedrina-app .` from the project root.
2. Run a single container for testing with `docker run -p 8000:8000 cedrina-app`.
3. For development with multiple services, use `docker-compose up` to start all defined services (`api`, `postgres`, `redis`).
4. Stop services with `docker-compose down`, and clean up volumes if needed with `docker-compose down -v`.
5. Override settings for different environments using additional Compose files (e.g., `docker-compose -f docker-compose.yml -f docker-compose.prod.yml up`).

This documentation provides a clear understanding of Docker configurations in the `cedrina` project, enabling developers to build, run, and customize containerized environments effectively. 