import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from passlib.context import CryptContext

from src.domain.services.auth.user_authentication import UserAuthenticationService
from src.domain.entities.user import User, Role
from src.core.exceptions import AuthenticationError, PasswordPolicyError, InvalidOldPasswordError, PasswordReuseError
from src.core.config.settings import BCRYPT_WORK_FACTOR


@pytest_asyncio.fixture
async def mock_db_session(mocker):
    """Create a properly mocked async database session."""
    async_mock = mocker.AsyncMock(spec=AsyncSession)
    async_mock.execute = mocker.AsyncMock()
    async_mock.commit = mocker.AsyncMock()
    async_mock.refresh = mocker.AsyncMock()
    async_mock.add = MagicMock()
    async_mock.get = mocker.AsyncMock()
    async_mock.exec = mocker.AsyncMock()
    return async_mock


@pytest_asyncio.fixture
async def user_auth_service(mock_db_session):
    """Create UserAuthenticationService instance with mocked dependencies."""
    return UserAuthenticationService(mock_db_session)


@pytest.fixture
def test_user():
    """Create a test user with valid credentials."""
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=BCRYPT_WORK_FACTOR)
    hashed_password = pwd_context.hash("OldPass123!")
    return User(
        id=1,
        username="testuser",
        email="test@example.com",
        hashed_password=hashed_password,
        role=Role.USER,
        is_active=True
    )


class TestChangePassword:
    """Test suite for change password functionality."""

    @pytest.mark.asyncio
    async def test_change_password_success(self, user_auth_service, mock_db_session, test_user):
        """Test successful password change with valid old and new passwords."""
        # Arrange
        old_password = "OldPass123!"
        new_password = "NewPass456!"
        
        # Mock the database session to return the test user
        mock_db_session.get.return_value = test_user
        
        # Act
        await user_auth_service.change_password(
            user_id=test_user.id,
            old_password=old_password,
            new_password=new_password
        )
        
        # Assert
        mock_db_session.commit.assert_called_once()
        mock_db_session.refresh.assert_called_once_with(test_user)
        
        # Verify the password was actually changed
        assert user_auth_service.pwd_context.verify(new_password, test_user.hashed_password)
        assert not user_auth_service.pwd_context.verify(old_password, test_user.hashed_password)

    @pytest.mark.asyncio
    async def test_change_password_invalid_old_password(self, user_auth_service, mock_db_session, test_user):
        """Test password change fails when old password is incorrect."""
        # Arrange
        old_password = "WrongOldPass123!"
        new_password = "NewPass456!"
        
        mock_db_session.get.return_value = test_user
        
        # Act & Assert
        with pytest.raises(InvalidOldPasswordError, match="Invalid old password"):
            await user_auth_service.change_password(
                user_id=test_user.id,
                old_password=old_password,
                new_password=new_password
            )
        
        # Verify no database changes were made
        mock_db_session.commit.assert_not_called()
        mock_db_session.refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_change_password_user_not_found(self, user_auth_service, mock_db_session):
        """Test password change fails when user doesn't exist."""
        # Arrange
        user_id = 999
        old_password = "OldPass123!"
        new_password = "NewPass456!"
        
        mock_db_session.get.return_value = None
        
        # Act & Assert
        with pytest.raises(AuthenticationError, match="User not found"):
            await user_auth_service.change_password(
                user_id=user_id,
                old_password=old_password,
                new_password=new_password
            )
        
        # Verify no database changes were made
        mock_db_session.commit.assert_not_called()
        mock_db_session.refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_change_password_inactive_user(self, user_auth_service, mock_db_session):
        """Test password change fails for inactive users."""
        # Arrange
        inactive_user = User(
            id=1,
            username="inactiveuser",
            email="inactive@example.com",
            hashed_password="hashed_password",
            role=Role.USER,
            is_active=False
        )
        
        old_password = "OldPass123!"
        new_password = "NewPass456!"
        
        mock_db_session.get.return_value = inactive_user
        
        # Act & Assert
        with pytest.raises(AuthenticationError, match="User account is inactive"):
            await user_auth_service.change_password(
                user_id=inactive_user.id,
                old_password=old_password,
                new_password=new_password
            )
        
        # Verify no database changes were made
        mock_db_session.commit.assert_not_called()
        mock_db_session.refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_change_password_weak_new_password(self, user_auth_service, mock_db_session, test_user):
        """Test password change fails when new password doesn't meet policy requirements."""
        # Arrange
        old_password = "OldPass123!"
        new_password = "weak"  # Too short, no uppercase, no digit, no special char
        
        mock_db_session.get.return_value = test_user
        
        # Act & Assert
        with pytest.raises(PasswordPolicyError, match="Password must be at least 8 characters long"):
            await user_auth_service.change_password(
                user_id=test_user.id,
                old_password=old_password,
                new_password=new_password
            )
        
        # Verify no database changes were made
        mock_db_session.commit.assert_not_called()
        mock_db_session.refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_change_password_same_password(self, user_auth_service, mock_db_session, test_user):
        """Test password change fails when new password is the same as old password."""
        # Arrange
        old_password = "OldPass123!"
        new_password = "OldPass123!"  # Same as old password
        
        mock_db_session.get.return_value = test_user
        
        # Act & Assert
        with pytest.raises(PasswordReuseError, match="New password must be different from the old password"):
            await user_auth_service.change_password(
                user_id=test_user.id,
                old_password=old_password,
                new_password=new_password
            )
        
        # Verify no database changes were made
        mock_db_session.commit.assert_not_called()
        mock_db_session.refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_change_password_new_password_no_uppercase(self, user_auth_service, mock_db_session, test_user):
        """Test password change fails when new password lacks uppercase letters."""
        # Arrange
        old_password = "OldPass123!"
        new_password = "newpass123!"  # No uppercase letters
        
        mock_db_session.get.return_value = test_user
        
        # Act & Assert
        with pytest.raises(PasswordPolicyError, match="Password must contain at least one uppercase letter"):
            await user_auth_service.change_password(
                user_id=test_user.id,
                old_password=old_password,
                new_password=new_password
            )

    @pytest.mark.asyncio
    async def test_change_password_new_password_no_lowercase(self, user_auth_service, mock_db_session, test_user):
        """Test password change fails when new password lacks lowercase letters."""
        # Arrange
        old_password = "OldPass123!"
        new_password = "NEWPASS123!"  # No lowercase letters
        
        mock_db_session.get.return_value = test_user
        
        # Act & Assert
        with pytest.raises(PasswordPolicyError, match="Password must contain at least one lowercase letter"):
            await user_auth_service.change_password(
                user_id=test_user.id,
                old_password=old_password,
                new_password=new_password
            )

    @pytest.mark.asyncio
    async def test_change_password_new_password_no_digit(self, user_auth_service, mock_db_session, test_user):
        """Test password change fails when new password lacks digits."""
        # Arrange
        old_password = "OldPass123!"
        new_password = "NewPass!"  # No digits
        
        mock_db_session.get.return_value = test_user
        
        # Act & Assert
        with pytest.raises(PasswordPolicyError, match="Password must contain at least one digit"):
            await user_auth_service.change_password(
                user_id=test_user.id,
                old_password=old_password,
                new_password=new_password
            )

    @pytest.mark.asyncio
    async def test_change_password_new_password_no_special_char(self, user_auth_service, mock_db_session, test_user):
        """Test password change fails when new password lacks special characters."""
        # Arrange
        old_password = "OldPass123!"
        new_password = "NewPass123"  # No special characters
        
        mock_db_session.get.return_value = test_user
        
        # Act & Assert
        with pytest.raises(PasswordPolicyError, match="Password must contain at least one special character"):
            await user_auth_service.change_password(
                user_id=test_user.id,
                old_password=old_password,
                new_password=new_password
            )

    @pytest.mark.asyncio
    async def test_change_password_database_error(self, user_auth_service, mock_db_session, test_user):
        """Test password change fails when database commit fails."""
        # Arrange
        old_password = "OldPass123!"
        new_password = "NewPass456!"
        
        mock_db_session.get.return_value = test_user
        mock_db_session.commit.side_effect = Exception("Database error")
        
        # Act & Assert
        with pytest.raises(Exception, match="Database error"):
            await user_auth_service.change_password(
                user_id=test_user.id,
                old_password=old_password,
                new_password=new_password
            )

    @pytest.mark.asyncio
    async def test_change_password_empty_passwords(self, user_auth_service, mock_db_session, test_user):
        """Test password change fails with empty passwords."""
        # Arrange
        mock_db_session.get.return_value = test_user
        
        # Act & Assert - Empty old password
        with pytest.raises(ValueError, match="Old password cannot be empty"):
            await user_auth_service.change_password(
                user_id=test_user.id,
                old_password="",
                new_password="NewPass456!"
            )
        
        # Act & Assert - Empty new password
        with pytest.raises(ValueError, match="New password cannot be empty"):
            await user_auth_service.change_password(
                user_id=test_user.id,
                old_password="OldPass123!",
                new_password=""
            )

    @pytest.mark.asyncio
    async def test_change_password_none_passwords(self, user_auth_service, mock_db_session, test_user):
        """Test password change fails with None passwords."""
        # Arrange
        mock_db_session.get.return_value = test_user
        
        # Act & Assert - None old password
        with pytest.raises(ValueError, match="Old password cannot be None"):
            await user_auth_service.change_password(
                user_id=test_user.id,
                old_password=None,
                new_password="NewPass456!"
            )
        
        # Act & Assert - None new password
        with pytest.raises(ValueError, match="New password cannot be None"):
            await user_auth_service.change_password(
                user_id=test_user.id,
                old_password="OldPass123!",
                new_password=None
            ) 