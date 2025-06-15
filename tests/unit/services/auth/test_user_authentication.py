import pytest
from domain.entities.user import User, Role
from domain.services.auth.user_authentication import UserAuthenticationService
from core.exceptions import AuthenticationError
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock

@pytest.fixture
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
    db_session.exec.return_value.first = MagicMock(return_value=user)

    # Act
    authenticated_user = await user_auth_service.authenticate_by_credentials(username, password)

    # Assert
    assert authenticated_user == user

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
    db_session.exec.return_value.first = MagicMock(return_value=user)

    # Act & Assert
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
    db_session.exec.return_value.first = MagicMock(return_value=user)

    # Act & Assert
    with pytest.raises(AuthenticationError, match="User account is inactive"):
        await user_auth_service.authenticate_by_credentials(username, password)

@pytest.mark.asyncio
async def test_register_user_success(user_auth_service, db_session, mocker):
    # Arrange
    username = "newuser"
    email = "newuser@example.com"
    password = "Newpass123"
    db_session.exec.return_value.first = MagicMock(return_value=None)
    
    mocker.patch.object(db_session, "refresh", new_callable=AsyncMock)

    # Act
    user = await user_auth_service.register_user(username, email, password)

    # Assert
    assert user.username == username
    assert user.email == email
    db_session.add.assert_called_once()
    db_session.commit.assert_called_once()
    db_session.refresh.assert_called_once_with(user)

@pytest.mark.asyncio
async def test_register_user_existing_username(user_auth_service, db_session):
    # Arrange
    username = "existinguser"
    email = "newuser@example.com"
    password = "newpassword"
    existing_user = User(username=username, email="other@example.com")
    db_session.exec.return_value.first = MagicMock(return_value=existing_user)

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Username already registered"):
        await user_auth_service.register_user(username, email, password)

@pytest.mark.asyncio
async def test_register_user_password_too_short(user_auth_service, db_session):
    # Arrange
    username = "newuser"
    email = "newuser@example.com"
    password = "short"
    db_session.exec.return_value.first = MagicMock(return_value=None)

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Password must be at least 8 characters long"):
        await user_auth_service.register_user(username, email, password)

@pytest.mark.asyncio
async def test_register_user_password_no_uppercase(user_auth_service, db_session):
    # Arrange
    username = "newuser"
    email = "newuser@example.com"
    password = "nouppercase123"
    db_session.exec.return_value.first = MagicMock(return_value=None)

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Password must contain at least one uppercase letter"):
        await user_auth_service.register_user(username, email, password)

@pytest.mark.asyncio
async def test_register_user_password_no_lowercase(user_auth_service, db_session):
    # Arrange
    username = "newuser"
    email = "newuser@example.com"
    password = "NOLOWERCASE123"
    db_session.exec.return_value.first = MagicMock(return_value=None)

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Password must contain at least one lowercase letter"):
        await user_auth_service.register_user(username, email, password)

@pytest.mark.asyncio
async def test_register_user_password_no_digit(user_auth_service, db_session):
    # Arrange
    username = "newuser"
    email = "newuser@example.com"
    password = "NoDigitHere"
    db_session.exec.return_value.first = MagicMock(return_value=None)

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Password must contain at least one digit"):
        await user_auth_service.register_user(username, email, password)