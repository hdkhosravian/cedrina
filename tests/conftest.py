import pytest
import sys
import os
from sqlalchemy.sql import text

# Adjust sys.path to include src directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from infrastructure.database.database import get_db_session, create_db_and_tables
from sqlmodel import SQLModel

@pytest.fixture(autouse=True, scope="function")
async def clean_database():
    """
    Ensure each test runs with a clean database state by truncating tables after the test.
    
    This fixture is automatically used for every test function (autouse=True) to provide database isolation,
    similar to tools like DatabaseCleaner in Ruby on Rails with RSpec. It ensures that data from one test
    does not affect another by resetting the database state after each test.
    
    Steps:
    1. Before the test: Creates all necessary database tables using create_db_and_tables().
    2. During the test: Yields control to the test, allowing it to interact with the database.
    3. After the test: Truncates all tables to remove any data created during the test.
    
    Note: Uses synchronous database operations with get_db_session() wrapped in a context manager.
    """
    # Setup: Create tables if needed
    create_db_and_tables()
    yield  # Run the test
    # Teardown: Truncate all tables to reset state
    with get_db_session() as session:
        for table in reversed(SQLModel.metadata.sorted_tables):
            session.exec(text(f"TRUNCATE TABLE {table.name} CASCADE"))
        session.commit() 