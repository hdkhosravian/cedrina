from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config.settings import BCRYPT_WORK_FACTOR
from src.core.exceptions import AuthenticationError, DuplicateUserError, PasswordPolicyError
from src.domain.entities.user import User
from src.domain.services.auth.password_policy import PasswordPolicyValidator
from src.domain.services.auth.user_authentication import UserAuthenticationService


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


def test_pwd_context_work_factor(user_auth_service):
    """Test that pwd_context is initialized with the configured BCRYPT_WORK_FACTOR."""
    # Check the rounds configured for bcrypt in pwd_context
    assert user_auth_service.pwd_context.schemes()[0] == "bcrypt"
    # Since direct access to rounds isn't available, we verify by hashing a password
    # and checking the format of the hash which includes the rounds
    hash = user_auth_service.pwd_context.hash("testpassword")
    # Extract rounds from the hash format $2b$<rounds>$...
    rounds_str = hash.split("$")[2]
    rounds = int(rounds_str)
    assert rounds == BCRYPT_WORK_FACTOR
