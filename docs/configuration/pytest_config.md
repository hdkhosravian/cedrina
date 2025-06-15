# Pytest Configuration Documentation for Cedrina

## Overview
Pytest is the testing framework used in the `cedrina` project for both unit and integration tests. This document explains the purpose of the Pytest configuration file, its contents, and how to customize it to meet testing requirements.

## Pytest Configuration File

### `pytest.ini`
- **What It Is**: The primary configuration file for Pytest, defining settings and behaviors for test execution.
- **What It Does**: Configures Pytest to set the Python path for proper module imports and enables loading of environment variables from `.env` files during testing via `pytest-dotenv`.
- **Key Contents**: 
  - `[pytest]` section with settings like `pythonpath = src` to ensure tests can import modules from the source directory.
  - Enables `dotenv` integration to load environment variables, making test configurations consistent with application settings.
- **Location**: Project root directory.
- **How to Customize**: 
  1. Add custom markers under `[pytest]` to categorize tests (e.g., `markers = slow: marks tests as slow`) for selective execution.
  2. Adjust `pythonpath` if the project structure changes or additional paths are needed for imports.
  3. Specify a different environment file for tests by setting `env_files = .env.test` if test-specific configurations are required.
  4. Configure test output or verbosity with options like `addopts = -v --cov=src` for detailed output and coverage reporting.
- **Important Notes**: Ensure `pytest.ini` is located at the project root for Pytest to detect it automatically. Customizations should align with testing workflows to avoid breaking CI/CD pipelines. Test changes by running `poetry run pytest` to confirm expected behavior.

## Customization Guidelines
- **Test Organization**: Use markers to organize tests by type or speed (e.g., `unit`, `integration`, `slow`) and customize `pytest.ini` to filter or prioritize them during runs.
- **Environment Consistency**: Ensure test environment variables match application settings where possible, or use a dedicated test `.env` file for isolation.
- **Version Control**: Commit `pytest.ini` to version control for consistent test configurations across the team.
- **Testing Changes**: After modifying `pytest.ini`, run a small subset of tests to verify the configuration works as expected before full test suite execution.

## How to Use
1. Run all tests with `poetry run pytest` from the project root to execute the test suite using settings from `pytest.ini`.
2. Filter tests using markers or paths (e.g., `poetry run pytest -m unit` to run only unit tests if markers are defined).
3. View detailed output or coverage with customized `addopts` (e.g., `poetry run pytest --cov=src` if configured).
4. Override environment files for specific test runs if needed (e.g., `pytest --envfile .env.test` with `pytest-dotenv` options).

This documentation provides a clear understanding of Pytest configuration in the `cedrina` project, enabling developers to configure and run tests effectively. 