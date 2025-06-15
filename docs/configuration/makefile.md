# Makefile Documentation for Cedrina

## Overview
The `Makefile` in the `cedrina` project is a build automation tool that defines tasks for building, running, testing, and maintaining the application. It provides shortcuts for common commands, streamlining development and deployment workflows. This document explains the purpose of the `Makefile`, its contents, and how to customize it for project-specific needs.

## Makefile

### `Makefile`
- **What It Is**: A configuration file for the `make` utility, defining build rules and tasks as targets with associated commands.
- **What It Does**: Automates repetitive tasks such as starting the development server, running tests, formatting code, managing Docker containers, and applying database migrations.
- **Key Contents**: 
  - Defines targets like `run-dev` (start development server), `test` (run test suite), `lint` (check code style), `format` (apply code formatting), `db-migrate` (apply database migrations), `clean` (remove temporary files), and Docker-related tasks (e.g., `run-dev`, `clean-volumes`).
  - Specifies dependencies between targets to ensure correct execution order (e.g., running tests after building).
  - Uses environment variables or shell commands to adapt to different setups.
- **Location**: Project root directory.
- **How to Customize**: 
  1. Add new targets for project-specific tasks (e.g., `seed-data` to populate the database with test data) by defining them with associated commands.
  2. Modify existing targets to use different tools or parameters (e.g., change test coverage options in the `test` target with `pytest --cov=src`).
  3. Include environment-specific targets (e.g., `run-staging` or `run-prod`) that load appropriate environment files or Docker Compose configurations.
  4. Use variables at the top of the file (e.g., `PYTHON=poetry run python`) to make commands adaptable to different environments or setups.
- **Important Notes**: Ensure `Makefile` commands are compatible with both local and Docker workflows. Test custom targets locally with `make <target>` to avoid breaking automated scripts or CI/CD processes. Commit the `Makefile` to version control for consistency across the team.

## Customization Guidelines
- **Task Automation**: Focus on automating repetitive or complex tasks to save time and reduce errors. Ensure targets are well-documented with comments (e.g., `# Run unit tests`) for clarity.
- **Environment Awareness**: Use environment variables or conditional logic in targets to handle differences between development, staging, and production (e.g., loading different `.env` files).
- **Version Control**: Commit the `Makefile` to Git to ensure all team members and pipelines use the same automation scripts.
- **Testing Changes**: After adding or modifying targets, test them with `make <target>` to confirm they execute as expected. Check for dependency issues or command failures.

## How to Use
1. List available targets with `make` or `make help` (if a help target is defined) to see what tasks are available.
2. Run a specific task with `make <target>` (e.g., `make run-dev` to start the development server).
3. Pass variables if supported (e.g., `make test TEST_FILE=tests/unit/test_specific.py` to run a specific test file, if the Makefile is set up for this).
4. Chain tasks if dependencies are defined (e.g., `make build test` to build and then test, assuming dependencies are set).

This documentation provides a clear understanding of the `Makefile` in the `cedrina` project, enabling developers to automate tasks and customize build processes effectively. 