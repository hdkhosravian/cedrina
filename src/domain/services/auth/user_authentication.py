from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import EmailStr
from structlog import get_logger

from src.core.exceptions import (
    AuthenticationError,
    UserAlreadyExistsError,
    InvalidCredentialsError,
    PasswordPolicyError,
    DuplicateUserError,
    InvalidOldPasswordError,
    PasswordReuseError,
)
from src.domain.entities.user import User, Role
from src.domain.services.auth.password_policy import PasswordPolicyValidator
from src.utils.i18n import get_translated_message
from src.core.config.settings import BCRYPT_WORK_FACTOR

logger = get_logger(__name__)

class UserAuthenticationService:
    """
    Service for handling username/password authentication and user registration.

    Provides secure authentication with bcrypt hashing, integrating
    with PostgreSQL via SQLAlchemy for user data persistence. This service
    enforces security best practices such as password hashing and validation
    to prevent common vulnerabilities.

    Attributes:
        db_session (AsyncSession): SQLAlchemy async session for database operations.
        pwd_context (CryptContext): Passlib context for bcrypt password hashing.
    """

    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=BCRYPT_WORK_FACTOR)

    async def authenticate_by_credentials(self, username: str, password: str) -> User:
        """
        Authenticate a user using username and password.

        Args:
            username (str): User's username.
            password (str): User's password.

        Returns:
            User: Authenticated user entity.

        Raises:
            AuthenticationError: If credentials are invalid or user is inactive.

        Note:
            This method uses bcrypt for secure password verification. Rate limiting
            should be applied at the API layer to prevent brute force attacks.
        """
        statement = select(User).where(User.username == username)
        result = await self.db_session.execute(statement)
        user = result.scalars().first()

        if not user or not self.pwd_context.verify(password, user.hashed_password):
            logger.warning("Invalid credentials for user", username=username)
            raise AuthenticationError(get_translated_message("invalid_username_or_password", "en"))
        
        if not user.is_active:
            logger.warning("Authentication attempt for inactive user", username=username)
            raise AuthenticationError(get_translated_message("user_account_inactive", "en"))
        
        return user

    async def register_user(self, username: str, email: EmailStr, password: str) -> User:
        """
        Register a new user with the provided username, email, and password.

        Args:
            username (str): Unique username for the new user.
            email (EmailStr): Unique email address for the new user.
            password (str): User password, must meet the password policy requirements.

        Returns:
            User: The newly created user entity.

        Raises:
            AuthenticationError: If username or email already exists, or if password
                does not meet policy requirements.
        """
        # Check for existing user
        statement = select(User).where((User.username == username) | (User.email == email))
        result = await self.db_session.execute(statement)
        existing = result.scalars().first()
        if existing:
            if existing.username == username:
                raise DuplicateUserError(get_translated_message("username_already_registered", "en"))
            if existing.email == email:
                raise DuplicateUserError(get_translated_message("email_already_registered", "en"))
        
        # Enforce password policy using PasswordPolicyValidator
        validator = PasswordPolicyValidator()
        try:
            validator.validate(password)
        except PasswordPolicyError as e:
            raise e  # Preserve the original PasswordPolicyError for proper status code handling
        
        hashed_password = self.pwd_context.hash(password)
        new_user = User(
            username=username,
            email=email,
            hashed_password=hashed_password,
            role=Role.USER,
            is_active=True
        )
        
        self.db_session.add(new_user)
        await self.db_session.commit()
        await self.db_session.refresh(new_user)
        
        logger.info("New user registered", username=username)
        return new_user

    async def change_password(self, user_id: int, old_password: str, new_password: str) -> None:
        """
        Change a user's password with comprehensive security validation.

        This method implements a secure password change process that:
        1. Validates input parameters (non-empty, non-None)
        2. Retrieves and validates the user exists and is active
        3. Verifies the old password is correct
        4. Ensures new password is different from old password
        5. Validates new password meets security policy requirements
        6. Securely hashes and stores the new password
        7. Logs the password change for audit purposes

        Args:
            user_id (int): The ID of the user whose password is being changed.
            old_password (str): The current password for verification.
            new_password (str): The new password to set.

        Raises:
            ValueError: If passwords are None or empty.
            AuthenticationError: If user not found or user inactive (401 status).
            InvalidOldPasswordError: If old password is incorrect (400 status).
            PasswordReuseError: If new password is the same as old password (400 status).
            PasswordPolicyError: If new password doesn't meet security policy requirements (422 status).

        Security Notes:
            - Uses bcrypt with configured work factor for secure hashing
            - Validates old password before allowing change (prevents unauthorized changes)
            - Enforces password policy to prevent weak passwords
            - Prevents password reuse by checking if new password differs from old
            - Logs password change events for security audit
            - Uses parameterized queries to prevent SQL injection
        """
        # Input validation
        if old_password is None:
            raise ValueError("Old password cannot be None")
        if new_password is None:
            raise ValueError("New password cannot be None")
        if not old_password.strip():
            raise ValueError("Old password cannot be empty")
        if not new_password.strip():
            raise ValueError("New password cannot be empty")

        # Retrieve user from database
        user = await self.db_session.get(User, user_id)
        if not user:
            logger.warning("Password change attempted for non-existent user", user_id=user_id)
            raise AuthenticationError(get_translated_message("user_not_found", "en"))

        # Check if user is active
        if not user.is_active:
            logger.warning("Password change attempted for inactive user", user_id=user_id, username=user.username)
            raise AuthenticationError(get_translated_message("user_account_inactive", "en"))

        # Verify old password
        if not self.pwd_context.verify(old_password, user.hashed_password):
            logger.warning("Invalid old password provided for password change", user_id=user_id, username=user.username)
            raise InvalidOldPasswordError(get_translated_message("invalid_old_password", "en"))

        # Check if new password is different from old password
        if old_password == new_password:
            logger.warning("Password change attempted with same password", user_id=user_id, username=user.username)
            raise PasswordReuseError(get_translated_message("new_password_must_be_different", "en"))

        # Validate new password against security policy
        validator = PasswordPolicyValidator()
        try:
            validator.validate(new_password)
        except PasswordPolicyError as e:
            logger.warning("Password change attempted with weak password", user_id=user_id, username=user.username)
            raise e

        # Hash and update the new password
        user.hashed_password = self.pwd_context.hash(new_password)
        
        # Commit changes to database
        await self.db_session.commit()
        await self.db_session.refresh(user)

        # Log successful password change for audit
        logger.info("Password successfully changed", user_id=user_id, username=user.username)