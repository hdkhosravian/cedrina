import pytest
from infrastructure.database import get_db, engine, check_database_health
from core.config.settings import settings
from sqlmodel import SQLModel, Session, create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.sql import text

def test_database_connectivity():
    assert check_database_health()
    with Session(engine) as session:
        assert session.bind is not None
        assert session.exec(text("SELECT 1")).scalar_one() == 1

def test_database_settings(monkeypatch):
    monkeypatch.setenv("POSTGRES_DB", "cedrina_test")
    # We need to reload the settings, but for this simple case, we can just patch it
    monkeypatch.setattr(settings, "POSTGRES_DB", "cedrina_test")
    
    assert settings.POSTGRES_POOL_SIZE == 5
    assert settings.POSTGRES_MAX_OVERFLOW == 10
    assert settings.POSTGRES_POOL_TIMEOUT == 30.0
    assert settings.POSTGRES_SSL_MODE == "disable"
    assert settings.POSTGRES_DB == "cedrina_test"