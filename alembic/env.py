import os
import sys
from logging.config import fileConfig
import logging
from sqlalchemy import engine_from_config, pool
from alembic import context

# Add project root to sys.path to ensure src module is importable
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, project_root)

from src.core.config.settings import settings
from sqlmodel import SQLModel

# Configure logging
config = context.config
try:
    fileConfig(config.config_file_name, disable_existing_loggers=False)
except KeyError as e:
    logging.warning(f"Logging configuration error: {e}. Falling back to default logging.")
    logging.basicConfig(level=logging.INFO)

# Set SQLAlchemy URL from settings
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Set up logger
logger = logging.getLogger("alembic.env")

# Define target metadata
target_metadata = SQLModel.metadata

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    logger.info("Running migrations in offline mode")
    run_migrations_offline()
else:
    logger.info("Running migrations in online mode")
    run_migrations_online()