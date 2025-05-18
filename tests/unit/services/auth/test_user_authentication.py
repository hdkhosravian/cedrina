import pytest
import pytest_asyncio
from unittest.mock import AsyncMock
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel
from pydantic import EmailStr
from passlib.context import CryptContext
from fastapi_limiter.depends import RateLimiter

from src.domain.entities.user import User, Role
from src.domain.services.auth.user_authentication import UserAuthenticationService
from src.core.exceptions import AuthenticationError, RateLimitError

@pytest_asyncio.fixture
async def db_session():
    return AsyncMock(spec=AsyncSession)

@pytest_asyncio.fixture
def user_auth_service(db_session):
    return UserAuthenticationService(db_session)

@pytest.mark.asyncio
async def test_authenticate_by_credentials_success(user_auth_service, db_session):
    # Arrange
    username = "testuser"
    password = "securepassword"
    hashed_password = user_auth_service.pwd_context.hash(password)
    user = User(
        id=1,
        username=username,
        email="test@example.com",
        hashed_password=hashed_password,
        role=Role.USER,
        is_active=True
    )
    db_session.exec.return_value.first.return_value = user

    # Act
    result = await user_auth_service.authenticate_by_credentials(username, password)

    # Assert
    assert result == user
    db_session.exec.assert_called_once()
    assert user_auth_service.pwd_context.verify(password, hashed_password)

@pytest.mark.asyncio
async def test_authenticate_by_credentials_invalid_password(user_auth_service, db_session):
    # Arrange
    username = "testuser"
    password = "wrongpassword"
    hashed_password = user_auth_service.pwd_context.hash("securepassword")
    user = User(
        id=1,
        username=username,
        hashed_password=hashed_password,
        is_active=True
    )
    db_session.exec.return_value.first.return_value = user

    # Act/Assert
    with pytest.raises(AuthenticationError, match="Invalid username or password"):
        await user_auth_service.authenticate_by_credentials(username, password)

@pytest.mark.asyncio
async def test_authenticate_by_credentials_inactive_user(user_auth_service, db_session):
    # Arrange
    username = "testuser"
    password = "securepassword"
    hashed_password = user_auth_service.pwd_context.hash(password)
    user = User(
        id=1,
        username=username,
        hashed_password=hashed_password,
        is_active=False
    )
    db_session.exec.return_value.first.return_value = user

    # Act/Assert
    with pytest.raises(AuthenticationError, match="User account is inactive"):
        await user_auth_service.authenticate_by_credentials(username, password)

@pytest.mark.asyncio
async def test_register_user_success(user_auth_service, db_session, mocker):
    # Arrange
    username = "newuser"
    email = EmailStr("newuser@example.com")
    password = "securepassword"
    db_session.exec.return_value.first.return_value = None
    mocker.patch.object(user_auth_service.pwd_context, "hash", return_value="hashed_password")

    # Act
    result = await user_auth_service.register_user(username, email, password)

    # Assert
    assert result.username == username
    assert result.email == email
    assert result.hashed_password == "hashed_password"
    assert result.role == Role.USER
    assert result.is_active
    db_session.add.assert_called_once()
    db_session.commit.assert_called_once()
    db_session.refresh.assert_called_once()

@pytest.mark.asyncio
async def test_register_user_existing_username(user_auth_service, db_session):
    # Arrange
    username = "existinguser"
    email = EmailStr("newuser@example.com")
    password = "securepassword"
    user = User(username=username, email="other@example.com")
    db_session.exec.return_value.first.return_value = user

    # Act/Assert
    with pytest.raises(AuthenticationError, match="Username or email already exists"):
        await user_auth_service.register_user(username, email, password)

@pytest.mark.asyncio
async def test_rate_limit_authentication(user_auth_service, db_session, mocker):
    # Arrange
    username = "testuser"
    password = "securepassword"
    mocker.patch("fastapi_limiter.depends.RateLimiter.__aenter__", side_effect=RateLimitError)

    # Act/Assert
    with pytest.raises(RateLimitError):
        await user_auth_service.authenticate_by_credentials(username, password)