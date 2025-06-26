import os
import sys
import pytest
import pytest_asyncio
from unittest.mock import patch, AsyncMock
from pytest_mock import MockerFixture
from fastapi import Request

# Adjust sys.path to include src directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from infrastructure.database.database import get_db_session, create_db_and_tables, AsyncSession, create_async_engine
from src.core.config.settings import settings
from sqlmodel import SQLModel
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport
from src.main import app
from src.domain.services.auth.token import TokenService
from src.domain.entities.user import User

@pytest.fixture(scope="session", autouse=True)
def setup_database():
    create_db_and_tables()

@pytest.fixture(scope="function", autouse=True)
def clean_database():
    """Clean up database state between tests to ensure isolation."""
    yield  # Run the test first
    
    # Clean up after each test
    try:
        from sqlalchemy import create_engine, text
        from src.core.config.settings import settings
        
        engine = create_engine(settings.DATABASE_URL)
        with engine.connect() as conn:
            # Clean up test data but keep essential admin policies
            # Remove policies added by tests but preserve core policies
            conn.execute(text("""
                DELETE FROM casbin_rule 
                WHERE v0 LIKE '%test%' 
                   OR v0 LIKE '%user_%' 
                   OR v0 = 'audit_test_user'
                   OR v0 = 'test_role_cycle'
                   OR v0 = 'test_regular_user_unique'
                   OR v1 LIKE '%test%' 
                   OR v1 LIKE '%rate-limit%'
                   OR v1 LIKE '%audit%'
                   OR v1 LIKE '%cycle%'
            """))
            
            # Also clean up audit logs from tests
            conn.execute(text("""
                DELETE FROM policy_audit_logs 
                WHERE subject LIKE '%test%' 
                   OR object LIKE '%test%'
                   OR subject = 'audit_test_user'
                   OR subject = 'test_role_cycle'
            """))
            
            conn.commit()
            
    except Exception as e:
        # Don't fail tests if cleanup fails
        print(f"Database cleanup warning: {e}")
        pass



@pytest_asyncio.fixture(scope="function")
async def async_session():
    async_engine = create_async_engine(settings.TEST_DATABASE_URL if hasattr(settings, 'TEST_DATABASE_URL') else settings.DATABASE_URL, echo=True)
    async with AsyncSession(async_engine) as session:
        yield session

@pytest_asyncio.fixture(scope="function")
async def async_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

@pytest.fixture(scope="function")
def client():
    with TestClient(app) as client:
        yield client

@pytest.fixture
async def admin_headers(async_client: AsyncClient, admin_user: User):
    token_service = TokenService()
    token = await token_service.create_access_token(admin_user)
    headers = {'Authorization': f'Bearer {token}'}
    return headers

@pytest.fixture
def mock_get_current_user(mocker: MockerFixture, admin_user: User):
    async def _mock_get_current_user(request: Request = None):
        return admin_user
    mocker.patch('src.core.dependencies.auth.get_current_user', _mock_get_current_user)
    return _mock_get_current_user

@pytest.fixture
def mock_enforce(mocker: MockerFixture):
    async def _mock_enforce(sub: str, obj: str, act: str, request: Request = None):
        return True
    mocker.patch('src.permissions.enforcer.enforce', _mock_enforce)
    return _mock_enforce

@pytest_asyncio.fixture(scope="function")
async def mock_token_service():
    with patch('src.domain.services.auth.token.TokenService', autospec=True) as mock:
        yield mock

@pytest_asyncio.fixture(scope="function")
async def mock_async_session():
    with patch('infrastructure.database.database.AsyncSessionLocal', autospec=True) as mock:
        yield mock

@pytest_asyncio.fixture(scope="function")
async def mock_user_service():
    with patch('src.domain.services.auth.user_authentication.UserAuthenticationService', autospec=True) as mock:
        yield mock

@pytest.fixture(scope='session', autouse=True)
def configure_rate_limiter():
    """Configure rate limiter for tests with same production settings."""
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    from src.main import app
    
    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    return limiter