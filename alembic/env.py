"""
Alembic environment configuration for database migrations.

This module configures the Alembic migration environment for SQLModel/SQLAlchemy.
It handles both online and offline migration modes, connecting to the database
using the application's settings and managing the migration process.

The module provides:
- Database URL configuration from application settings
- Migration metadata from SQLModel
- Online and offline migration runners
- Connection pooling configuration
- Transaction management
"""

from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context
from src.core.config.settings import settings
from sqlmodel import SQLModel

# Get the Alembic configuration
config = context.config

# Set the database URL from application settings
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Configure logging
fileConfig(config.config_file_name)

# Get the SQLModel metadata for migrations
target_metadata = SQLModel.metadata

def run_migrations_offline():
    """
    Run migrations in 'offline' mode.
    
    This function is called when alembic is run with the --sql flag.
    It generates SQL scripts without connecting to the database.
    
    The function:
    1. Gets the database URL from the config
    2. Configures the Alembic context
    3. Runs the migrations in a transaction
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    """
    Run migrations in 'online' mode.
    
    This function is called when alembic is run normally.
    It connects to the database and applies migrations directly.
    
    The function:
    1. Creates a database engine from the config
    2. Establishes a connection
    3. Configures the Alembic context
    4. Runs the migrations in a transaction
    
    Note:
        Uses NullPool to avoid connection pooling issues during migrations
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

# Determine which migration mode to use
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()