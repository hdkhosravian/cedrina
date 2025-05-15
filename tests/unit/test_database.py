import pytest
from sqlmodel import Session
from src.infrastructure.database import get_db, engine, check_database_health
from src.core.config.settings import settings

def test_database_connectivity():
    assert check_database_health()
    with Session(engine) as session:
        assert session.bind is not None
        assert session.exec("SELECT 1").first() == 1

def test_database_settings():
    assert settings.POSTGRES_POOL_SIZE == 5
    assert settings.POSTGRES_MAX_OVERFLOW == 10
    assert settings.POSTGRES_POOL_TIMEOUT == 30.0
    assert settings.POSTGRES_SSL_MODE == "prefer"
    assert settings.POSTGRES_DB == "cedrina_test"