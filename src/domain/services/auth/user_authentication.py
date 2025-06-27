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
            raise AuthenticationError(str(e))
        
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