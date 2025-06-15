# Alembic Configuration Documentation for Cedrina

## Overview
Alembic is a database migration tool used in the `cedrina` project to manage schema changes for the PostgreSQL database. This document explains the purpose of Alembic configuration files, their contents, and how to customize them to handle database migrations effectively.

## Alembic Configuration Files

### 1. `alembic/env.py`
- **What It Is**: The environment script for Alembic, configuring the migration context.
- **What It Does**: Sets up the connection to the database using `settings.DATABASE_URL`, configures logging, and defines the `target_metadata` for SQLModel to detect and apply schema changes.
- **Key Contents**: 
  - Imports necessary modules and settings from the application.
  - Configures the Alembic context with database connection details.
  - Defines functions like `run_migrations_offline()` and `run_migrations_online()` to handle migration execution modes.
- **Location**: `alembic/` directory in the project root.
- **How to Customize**: 
  1. Modify the database connection logic to use a different URL or connection method if needed (e.g., for a connection pool or different environment).
  2. Add custom pre-migration or post-migration hooks (e.g., logging, backup creation) within the migration functions.
  3. Adjust `target_metadata` if using a different ORM or model structure.
- **Important Notes**: Customizing `env.py` requires understanding Alembic's internals. Test changes in a development environment to ensure migrations run without errors. Backup the database before testing new migration configurations.

### 2. `alembic/script.py.mako`
- **What It Is**: A template file used by Alembic to generate new migration scripts.
- **What It Does**: Provides a structure for migration scripts, including revision metadata and placeholders for `upgrade()` and `downgrade()` functions where schema changes are defined.
- **Key Contents**: 
  - Defines revision details like `revision`, `down_revision`, and `branch_labels`.
  - Includes empty `upgrade()` and `downgrade()` functions for adding schema changes.
- **Location**: `alembic/` directory in the project root.
- **How to Customize**: 
  1. Update the template to include custom comments or metadata (e.g., author, date) for better tracking of migration scripts.
  2. Add default boilerplate code or checks in `upgrade()` and `downgrade()` functions to enforce migration standards.
  3. Modify the structure to support project-specific migration patterns if needed.
- **Important Notes**: Changes to this template affect only new migration scripts generated with `alembic revision`. Test the template by generating a new migration to ensure it meets project documentation or formatting standards.

## Customization Guidelines
- **Environment Awareness**: Ensure `env.py` can handle database connections for different environments (development, staging, production) by using environment variables or conditional logic.
- **Security**: Protect database credentials in `env.py` by sourcing them from secure environment variables or secret management tools, not hardcoding them.
- **Version Control**: Commit both `env.py` and `script.py.mako` to version control for consistency. Also, commit generated migration scripts in `alembic/versions/` to track schema history.
- **Testing Changes**: Test customizations by running `alembic upgrade head` in a non-production environment with a database backup. Verify that migrations apply correctly and schema changes are as expected.

## How to Use
1. Generate a new migration script with `poetry run alembic revision --autogenerate -m "Description of change"` to detect model changes and create a script in `alembic/versions/`.
2. Review and edit the generated script's `upgrade()` and `downgrade()` functions to ensure accuracy, as autogeneration may not capture all nuances.
3. Apply migrations to the database with `poetry run alembic upgrade head` (or `make db-migrate` if defined in Makefile).
4. Revert migrations if needed with `poetry run alembic downgrade -1` to roll back the last migration.
5. Check migration history with `poetry run alembic history` to see applied revisions.

This documentation provides a clear understanding of Alembic configurations in the `cedrina` project, enabling developers to manage database schema changes and customize migration behaviors effectively. 