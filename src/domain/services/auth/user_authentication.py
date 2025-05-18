from pydantic import EmailStr
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select
from fastapi_limiter.depends import RateLimiter
from structlog import get_logger

from src.domain.entities.user import User, Role
from src.core.exceptions import AuthenticationError

logger = get_logger(__name__)

class UserAuthenticationService:
    """
    Service for handling username/password authentication and user registration.

    Provides secure authentication with bcrypt hashing and rate limiting, integrating
    with PostgreSQL via SQLModel for user data persistence.

    Attributes:
        db_session (AsyncSession): SQLAlchemy async session for database operations.
        pwd_context (CryptContext): Passlib context for bcrypt password hashing.
    """

    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    async def authenticate_by_credentials(self, username: str, password: str) -> User:
        """
        Authenticate a user using username and password with rate limiting.

        Args:
            username (str): User's username.
            password (str): User's password.

        Returns:
            User: Authenticated user entity.

        Raises:
            AuthenticationError: If credentials are invalid or user is inactive.
            RateLimitError: If login attempts exceed rate limit (5/minute).
        """
        async with RateLimiter(times=5, seconds=60, identifier=f"login:{username}"):
            user = await self.db_session.exec(
                select(User).where(User.username == username)
            )
            user = user.first()
            if not user or not self.pwd_context.verify(password, user.hashed_password):
                await logger.awarning("Invalid login attempt", username=username)
                raise AuthenticationError("Invalid username or password")
            if not user.is_active:
                await logger.awarning("Inactive user login attempt", username=username)
                raise AuthenticationError("User account is inactive")
            await logger.ainfo("User authenticated", username=username, user_id=user.id)
            return user

    async def register_user(self, username: str, email: EmailStr, password: str) -> User:
        """
        Register a new user with validated credentials.

        Args:
            username (str): Unique username.
            email (EmailStr): Unique email address.
            password (str): User password.

        Returns:
            User: Newly created user entity.

        Raises:
            AuthenticationError: If username or email already exists.
            RateLimitError: If registration attempts exceed rate limit (3/minute).
        """
        async with RateLimiter(times=3, seconds=60, identifier=f"register:{username}"):
            existing_user = await self.db_session.exec(
                select(User).where((User.username == username) | (User.email == email))
            )
            if existing_user.first():
                await logger.awarning("Registration attempt with existing credentials", username=username)
                raise AuthenticationError("Username or email already exists")

            hashed_password = self.pwd_context.hash(password)
            user = User(
                username=username,
                email=email,
                hashed_password=hashed_password,
                role=Role.USER,
                is_active=True
            )
            self.db_session.add(user)
            await self.db_session.commit()
            await self.db_session.refresh(user)
            await logger.ainfo("User registered", username=username, user_id=user.id)
            return user