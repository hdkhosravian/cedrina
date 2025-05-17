"""
Alembic environment configuration for Cedrina's database migrations.

This script sets up the migration context, connects to the database using settings.DATABASE_URL,
and defines the target metadata for SQLModel models. It dynamically adds the project root to
sys.path to support the src/ layout.
"""
import sys  # For modifying sys.path
import os  # For path manipulation
from logging.config import fileConfig  # For configuring logging
from sqlalchemy import engine_from_config, pool  # For database connection
from alembic import context  # For migration context

# Add project root to sys.path to resolve src/ imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))  # Parent of alembic/
if project_root not in sys.path:
    sys.path.insert(0, project_root)  # Prepend to ensure priority

from src.core.config.settings import settings  # Import settings after path adjustment
from src.domain.entities.user import User  # User model
from src.domain.entities.oauth_profile import OAuthProfile  # OAuthProfile model
from src.domain.entities.session import Session  # Session model
from sqlmodel import SQLModel  # For metadata

# Alembic Config object, provides access to alembic.ini
config = context.config

# Set database URL from settings for consistency with FastAPI
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Configure logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for SQLModel models, includes all defined tables
target_metadata = SQLModel.metadata

def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode, generating SQL scripts without a database connection.
    
    This mode is used for generating migration scripts for external application or documentation.
    """
    url = config.get_main_option("sqlalchemy.url")  # Database URL from config
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,  # Use literal SQL values
        dialect_opts={"paramstyle": "named"},  # Named parameters for SQL
    )

    with context.begin_transaction():
        context.run_migrations()  # Generate SQL scripts

def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode, connecting to the database.
    
    This mode applies migrations directly to the database specified in settings.DATABASE_URL.
    Uses a non-pooled connection to avoid conflicts during migrations.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),  # Database config from alembic.ini
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,  # Disable pooling for migrations
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()  # Apply migrations

if context.is_offline_mode():
    run_migrations_offline()  # Run offline migrations
else:
    run_migrations_online()  # Run online migrations