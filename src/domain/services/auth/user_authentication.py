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
)
from src.domain.entities.user import User, Role
from src.domain.services.auth.password_policy import PasswordPolicyValidator

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
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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
        user = (await self.db_session.exec(statement)).first()

        if not user or not self.pwd_context.verify(password, user.hashed_password):
            logger.warning("Invalid credentials for user", username=username)
            raise AuthenticationError("Invalid username or password")
        
        if not user.is_active:
            logger.warning("Authentication attempt for inactive user", username=username)
            raise AuthenticationError("User account is inactive")
        
        return user

    async def register_user(self, username: str, email: EmailStr, password: str) -> User:
        """
        Register a new user with validated credentials.

        Args:
            username (str): Unique username.
            email (EmailStr): Unique email address.
            password (str): User password, must be at least 8 characters long and include
                           at least one uppercase letter, one lowercase letter, and one digit.

        Returns:
            User: Newly created user entity.

        Raises:
            AuthenticationError: If username or email already exists, or if password
                                 does not meet security requirements.
        """
        # Check for existing username
        statement = select(User).where(User.username == username)
        if (await self.db_session.exec(statement)).first():
            raise AuthenticationError("Username already registered")

        # Check for existing email
        statement = select(User).where(User.email == email)
        if (await self.db_session.exec(statement)).first():
            raise AuthenticationError("Email already registered")
        
        # Enforce password policy
        if len(password) < 8:
            raise AuthenticationError("Password must be at least 8 characters long")
        if not any(c.isupper() for c in password):
            raise AuthenticationError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in password):
            raise AuthenticationError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in password):
            raise AuthenticationError("Password must contain at least one digit")
        
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