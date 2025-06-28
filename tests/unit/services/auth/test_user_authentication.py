import pytest
from src.domain.entities.user import User, Role
from src.domain.services.auth.user_authentication import UserAuthenticationService
from src.core.exceptions import AuthenticationError, DuplicateUserError, PasswordPolicyError
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock
from src.domain.services.auth.password_policy import PasswordPolicyValidator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from src.core.config.settings import BCRYPT_WORK_FACTOR

@pytest_asyncio.fixture
async def mock_db_session(mocker):
    async_mock = mocker.AsyncMock(spec=AsyncSession)
    async_mock.execute = mocker.AsyncMock()
    async_mock.scalar_one_or_none = mocker.AsyncMock()
    async_mock.commit = mocker.AsyncMock()
    async_mock.rollback = mocker.AsyncMock()
    # Simulate async context manager behavior
    async_mock.__aenter__ = mocker.AsyncMock(return_value=async_mock)
    async_mock.__aexit__ = mocker.AsyncMock(return_value=None)
    yield async_mock

@pytest_asyncio.fixture
async def mock_password_policy(mocker):
    mock = mocker.AsyncMock(spec=PasswordPolicyValidator)
    mock.validate.return_value = None  # No exception means password is valid
    mock.pwd_context = MagicMock()
    return mock

@pytest_asyncio.fixture
async def user_auth_service(mock_db_session):
    return UserAuthenticationService(db_session=mock_db_session)

@pytest.mark.asyncio
async def test_authenticate_by_credentials_success(user_auth_service, mock_db_session):
    # Arrange
    username = "testuser"
    password = "securepassword"
    hashed_password = user_auth_service.pwd_context.hash(password)
    user = User(
        id=1,
        username=username,
        hashed_password=hashed_password,
        is_active=True
    )
    # Mock the execute method to return a result with scalars()
    result = MagicMock()
    scalars_result = MagicMock()
    scalars_result.first.return_value = user
    result.scalars.return_value = scalars_result
    mock_db_session.execute.return_value = result

    # Act
    authenticated_user = await user_auth_service.authenticate_by_credentials(username, password)

    # Assert
    assert authenticated_user == user
    mock_db_session.execute.assert_called_once()

@pytest.mark.asyncio
async def test_authenticate_by_credentials_invalid_password(user_auth_service, mock_db_session):
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
    # Mock the execute method to return a result with scalars()
    result = MagicMock()
    scalars_result = MagicMock()
    scalars_result.first.return_value = user
    result.scalars.return_value = scalars_result
    mock_db_session.execute.return_value = result

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Invalid username or password"):
        await user_auth_service.authenticate_by_credentials(username, password)

@pytest.mark.asyncio
async def test_authenticate_by_credentials_inactive_user(user_auth_service, mock_db_session):
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
    # Mock the execute method to return a result with scalars()
    result = MagicMock()
    scalars_result = MagicMock()
    scalars_result.first.return_value = user
    result.scalars.return_value = scalars_result
    mock_db_session.execute.return_value = result

    # Act & Assert
    with pytest.raises(AuthenticationError, match="User account is inactive"):
        await user_auth_service.authenticate_by_credentials(username, password)

@pytest.mark.asyncio
async def test_register_user_success(user_auth_service, mock_db_session, mocker):
    # Arrange
    username = "newuser"
    email = "newuser@example.com"
    password = "Newpass123!"
    # Mock the execute method to return a result with scalars()
    result = MagicMock()
    scalars_result = MagicMock()
    scalars_result.first.return_value = None
    result.scalars.return_value = scalars_result
    mock_db_session.execute.return_value = result
    mock_db_session.add = MagicMock()
    mock_db_session.commit = mocker.AsyncMock()
    mock_db_session.refresh = mocker.AsyncMock()

    # Act
    user = await user_auth_service.register_user(username, email, password)

    # Assert
    assert user.username == username
    assert user.email == email
    assert user.hashed_password != password  # Ensure password is hashed

@pytest.mark.asyncio
async def test_register_user_invalid_password(user_auth_service, mock_db_session):
    # Arrange
    username = "newuser"
    email = "newuser@example.com"
    password = "short"
    # Mock the execute method to return a result with scalars()
    result = MagicMock()
    scalars_result = MagicMock()
    scalars_result.first.return_value = None
    result.scalars.return_value = scalars_result
    mock_db_session.execute.return_value = result

    # Act & Assert
    with pytest.raises(PasswordPolicyError, match="Password must be at least 8 characters long"):
        await user_auth_service.register_user(username, email, password)

@pytest.mark.asyncio
async def test_register_user_existing_username(user_auth_service, mock_db_session):
    # Arrange
    username = "existinguser"
    email = "newuser@example.com"
    password = "Newpass123!"
    existing_user = User(id=1, username=username, email="old@example.com")
    # Mock the execute method to return a result with scalars()
    result = MagicMock()
    scalars_result = MagicMock()
    scalars_result.first.return_value = existing_user
    result.scalars.return_value = scalars_result
    mock_db_session.execute.return_value = result

    # Act & Assert
    with pytest.raises(DuplicateUserError, match="Username already registered"):
        await user_auth_service.register_user(username, email, password)

@pytest.mark.asyncio
async def test_register_user_existing_email(user_auth_service, mock_db_session):
    # Arrange
    username = "newuser"
    email = "existing@example.com"
    password = "Newpass123!"
    existing_user = User(id=1, username="olduser", email=email)
    # Mock the execute method to return a result with scalars()
    result = MagicMock()
    scalars_result = MagicMock()
    scalars_result.first.return_value = existing_user
    result.scalars.return_value = scalars_result
    mock_db_session.execute.return_value = result

    # Act & Assert
    with pytest.raises(DuplicateUserError, match="Email already registered"):
        await user_auth_service.register_user(username, email, password)

def test_pwd_context_work_factor(user_auth_service):
    """
    Test that pwd_context is initialized with the configured BCRYPT_WORK_FACTOR.
    """
    # Check the rounds configured for bcrypt in pwd_context
    assert user_auth_service.pwd_context.schemes()[0] == "bcrypt"
    # Since direct access to rounds isn't available, we verify by hashing a password
    # and checking the format of the hash which includes the rounds
    hash = user_auth_service.pwd_context.hash("testpassword")
    # Extract rounds from the hash format $2b$<rounds>$...
    rounds_str = hash.split('$')[2]
    rounds = int(rounds_str)
    assert rounds == BCRYPT_WORK_FACTOR