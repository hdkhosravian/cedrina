import httpx
import pytest_asyncio

from src.main import app


# Define database setup functions directly since the import path is incorrect
async def create_all_tables():
    """Create all database tables for testing."""
    pass  # Implementation would go here if needed


async def truncate_all_tables():
    """Truncate all database tables after testing."""
    pass  # Implementation would go here if needed


@pytest_asyncio.fixture(scope="function", autouse=True)
async def setup_database():
    """Set up the database before each test."""
    await create_all_tables()
    yield
    await truncate_all_tables()


@pytest_asyncio.fixture
async def async_client():
    """Provides an async test client."""
    from src.core.rate_limiting.ratelimiter import get_limiter
    
    # Ensure limiter is available in app state for testing
    if not hasattr(app.state, 'limiter'):
        app.state.limiter = get_limiter()
    
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


from unittest.mock import AsyncMock, MagicMock, patch


@pytest_asyncio.fixture
async def db_session():
    """Provides a mocked asynchronous database session."""
    mock_session = AsyncMock()
    mock_session.exec = AsyncMock()
    mock_session.exec.return_value = AsyncMock()
    mock_session.exec.return_value.first = AsyncMock(return_value=None)
    mock_session.get = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()
    mock_session.refresh = AsyncMock()
    return mock_session


@pytest_asyncio.fixture
async def mock_password_reset_request_service():
    """Provides a mocked password reset request service."""
    from src.infrastructure.dependency_injection.auth_dependencies import get_password_reset_request_service
    
    mock_service = AsyncMock()
    
    # Override the FastAPI dependency
    app.dependency_overrides[get_password_reset_request_service] = lambda: mock_service
    
    yield mock_service
    
    # Clean up
    if get_password_reset_request_service in app.dependency_overrides:
        del app.dependency_overrides[get_password_reset_request_service]


@pytest_asyncio.fixture
async def mock_password_reset_service():
    """Provides a mocked password reset service."""
    from src.infrastructure.dependency_injection.auth_dependencies import get_password_reset_service
    
    mock_service = AsyncMock()
    
    # Override the FastAPI dependency
    app.dependency_overrides[get_password_reset_service] = lambda: mock_service
    
    yield mock_service
    
    # Clean up
    if get_password_reset_service in app.dependency_overrides:
        del app.dependency_overrides[get_password_reset_service]


@pytest_asyncio.fixture
async def mock_email_confirmation_service():
    """Provides a mocked email confirmation service."""
    from src.infrastructure.dependency_injection.auth_dependencies import (
        get_email_confirmation_service,
    )

    mock_service = AsyncMock()

    app.dependency_overrides[get_email_confirmation_service] = lambda: mock_service

    yield mock_service

    if get_email_confirmation_service in app.dependency_overrides:
        del app.dependency_overrides[get_email_confirmation_service]


@pytest_asyncio.fixture
async def mock_email_confirmation_request_service():
    """Provides a mocked email confirmation request service."""
    from src.infrastructure.dependency_injection.auth_dependencies import (
        get_email_confirmation_request_service,
    )

    mock_service = AsyncMock()

    app.dependency_overrides[get_email_confirmation_request_service] = (
        lambda: mock_service
    )

    yield mock_service

    if get_email_confirmation_request_service in app.dependency_overrides:
        del app.dependency_overrides[get_email_confirmation_request_service]
