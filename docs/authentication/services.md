# Authentication Services

## Overview
The Cedrina authentication system comprises a set of modular **authentication services** in `src/domain/services/auth/`, designed to handle user authentication, OAuth 2.0 flows, JWT token management, and session tracking. These services include:

- **UserAuthenticationService**: Manages username/password authentication and user registration.
- **OAuthService**: Handles OAuth 2.0 flows for Google, Microsoft, and Facebook.
- **TokenService**: Issues, validates, and refreshes JWT access and refresh tokens.
- **SessionService**: Tracks sessions and manages refresh token revocation.

Built with **Domain-Driven Design (DDD)** principles, the services integrate with PostgreSQL (`sqlmodel`), Redis, and external OAuth providers, ensuring **enterprise-grade security**, **scalability**, and **maintainability**. They leverage **RS256 JWT signing**, **bcrypt hashing**, **pgcrypto encryption**, **rate limiting**, and **structured logging**, following **SOLID principles**, **Clean Architecture**, and **advanced design patterns**.

This document describes each service, its responsibilities, methods, security measures, and testing instructions, complementing the models (`User`, `OAuthProfile`, `Session`) and setup instructions in `docs/authentication/`.

## Authentication Services

### UserAuthenticationService
**File**: `src/domain/services/auth/user_authentication.py`

**Purpose**: Handles username/password authentication and user registration with secure bcrypt hashing and rate limiting.

**Responsibilities**:
- Authenticate users via username and password.
- Register new users with validated credentials.
- Enforce rate limits on login (5 attempts/minute) and registration (3 attempts/minute).
- Enforce password policies for user registration.

**Methods**:
- `__init__(db_session: AsyncSession)`: Initializes with an async SQLAlchemy session.
- `authenticate_by_credentials(username: str, password: str) -> User`: Authenticates a user, verifying password and activity.
- `register_user(username: str, email: EmailStr, password: str) -> User`: Registers a new user with bcrypt-hashed password, enforcing password complexity requirements.
- `change_password(user_id: int, current_password: str, new_password: str) -> None`: Updates a user's password after verifying the current password and enforcing policy rules.

**Security**:
- Bcrypt hashing via `passlib`.
- Rate limiting with `fastapi-limiter` and Redis.
- Structured logging with `structlog`.
- Password policy enforcement (minimum 8 characters, must include uppercase, lowercase, and digit).
- Raises `AuthenticationError` for invalid credentials, inactive users, or password policy violations.
- Raises `RateLimitError` for excessive attempts.

### OAuthService
**File**: `src/domain/services/auth/oauth.py`

**Purpose**: Manages OAuth 2.0 authentication flows for Google, Microsoft, and Facebook, linking or creating user profiles.

**Responsibilities**:
- Authenticate users via OAuth providers.
- Fetch user info with retry logic.
- Encrypt OAuth access tokens with `pgcrypto`.
- Provide mechanisms for state validation to prevent CSRF attacks.

**Methods**:
- `__init__(db_session: AsyncSession)`: Initializes with OAuth clients and Fernet encryption.
- `authenticate_with_oauth(provider: str, token: Dict) -> Tuple[User, OAuthProfile]`: Authenticates and links/creates profiles.
- `_fetch_user_info(provider: str, token: Dict) -> Dict`: Fetches user info with retries.
- `validate_oauth_state(state: str, stored_state: str) -> bool`: Validates the OAuth state parameter to prevent CSRF attacks (placeholder for implementation).

**Security**:
- Token encryption with `cryptography.Fernet`.
- Retry logic with `tenacity`.
- Validation of user info and token expiration.
- Placeholder for state validation to mitigate CSRF risks.
- Raises `AuthenticationError` for invalid OAuth data or expired tokens.

### TokenService
**File**: `src/domain/services/auth/token.py`

**Purpose**: Issues, validates, and refreshes JWT access and refresh tokens with RS256 signing.

**Responsibilities**:
- Create short-lived access tokens (15 minutes) and long-lived refresh tokens (7 days).
- Validate tokens for issuer, audience, expiration, and user status.
- Rotate refresh tokens, invalidating old ones.
- Provide mechanisms for token blacklisting.

**Methods**:
- `__init__(db_session: AsyncSession, redis_client: Redis)`: Initializes with database and Redis clients.
- `create_access_token(user: User) -> str` (async): Creates an access token with advanced claims.
- `create_refresh_token(user: User, jti: str) -> str` (async): Creates a refresh token, storing in Redis/PostgreSQL.
- `refresh_tokens(refresh_token: str) -> Dict[str, str]` (async): Refreshes tokens with rotation.
- `validate_token(token: str) -> Dict[str, Any]` (async): Validates a token's integrity, claims, and checks for blacklisting.
- `_is_token_blacklisted(jti: str) -> bool` (async): Placeholder for checking if a token's JTI is blacklisted.

**Security**:
- RS256 signing with RSA key pair.
- Single-use refresh tokens stored as hashes in Redis.
- Comprehensive claim validation (issuer, audience, expiration).
- Placeholder for token blacklisting to handle compromised or revoked tokens.
- Raises `AuthenticationError` for invalid, expired, or blacklisted tokens.
- Note: The `TokenPair` response model now includes an `expires_in` field indicating the access token's expiration time in seconds.

### SessionService
**File**: `src/domain/services/auth/session.py`

**Purpose**: Manages user sessions and refresh token revocation in PostgreSQL and Redis.

**Responsibilities**:
- Create and store sessions.
- Revoke sessions on logout or refresh.
- Validate session status.

**Methods**:
- `__init__(db_session: AsyncSession, redis_client: Redis)`: Initializes with database and Redis clients.
- `create_session(user_id: int, jti: str, refresh_token_hash: str, expires_at: datetime) -> Session`: Creates a session.
- `revoke_session(jti: str, user_id: int) -> None`: Revokes a session.
- `get_session(jti: str, user_id: int) -> Optional[Session]`: Retrieves a session.
- `is_session_valid(jti: str, user_id: int) -> bool`: Checks session validity.

**Security**:
- Session revocation in PostgreSQL and Redis.
- Expiration checks.
- Raises `AuthenticationError` for invalid sessions.

## Exceptions
Custom exceptions in `src/core/exceptions.py` handle authentication and rate limiting errors:

- **AuthenticationError**: Raised for invalid credentials, inactive users, invalid tokens, or password policy violations.
  - Attributes: `message` (error description), `code` (i18n key, e.g., "authentication_error").
- **RateLimitError**: Raised when rate limits are exceeded.
  - Attributes: `message` (default: "Rate limit exceeded"), `code` (e.g., "rate_limit_exceeded").

These exceptions support multilingual error messages via `python-i18n` and are used across all services.

## Architecture and Design
- **SOLID Principles**:
  - **Single Responsibility**: Each service focuses on a specific authentication aspect.
  - **Open/Closed**: Extensible for new OAuth providers or token types.
  - **Liskov Substitution**: Services can be mocked for testing.
  - **Interface Segregation**: Clear, focused method signatures.
  - **Dependency Inversion**: Inject `db_session` and `redis_client`.
- **Clean Architecture**: Domain logic is isolated from infrastructure.
- **Design Patterns**:
  - **Repository Pattern**: Abstracts database/Redis access.
  - **Dependency Injection**: Enhances testability.
  - **Retry Pattern**: Used in `OAuthService`.
- **Type Safety**: MyPy compliance with strict typing.
- **Async Performance**: All methods are async for non-blocking operations.
- **Logging**: Structured logging with `structlog`.

## Dependencies
- **sqlmodel**: ORM for entities.
- **redis**: Token storage and rate limiting.
- **python-jose[cryptography]**: JWT operations.
- **authlib**: OAuth client.
- **passlib[bcrypt]**: Password hashing.
- **fastapi-limiter**: Rate limiting.
- **cryptography**: Token encryption.
- **structlog**: Logging.
- **tenacity**: Retries.

## Usage
Services are used via FastAPI dependency injection (endpoints pending in `src/adapters/api/v1/auth.py`). Example:

```python
from fastapi import Depends
from src.domain.services.auth.user_authentication import UserAuthenticationService
from src.domain.services.auth.token import TokenService

async def get_user_auth_service(db_session: AsyncSession) -> UserAuthenticationService:
    return UserAuthenticationService(db_session)

async def get_token_service(db_session: AsyncSession, redis_client: Redis) -> TokenService:
    return TokenService(db_session, redis_client)

@app.post("/api/v1/auth/login")
async def login(
    credentials: LoginSchema,
    user_auth: UserAuthenticationService = Depends(get_user_auth_service),
    token_service: TokenService = Depends(get_token_service)
):
    user = await user_auth.authenticate_by_credentials(credentials.username, credentials.password)
    tokens = await token_service.create_jwt_tokens(user)
    return tokens
```

## Verification
After endpoint implementation:

1. **Test Login**:
   ```bash
   curl -X POST http://localhost:8000/api/v1/auth/login -d '{"username": "testuser", "password": "securepassword"}' -H "Content-Type: application/json"
   ```

2. **Test OAuth**:
   - Navigate to `http://localhost:8000/api/v1/auth/google/login`.
   - Complete OAuth flow.

3. **Test Refresh**:
   ```bash
   curl -X POST http://localhost:8000/api/v1/auth/refresh -d '{"refresh_token": "your-refresh-token"}' -H "Content-Type: application/json"
   ```

4. **Test Change Password**:
   ```bash
   curl -X POST http://localhost:8000/api/v1/auth/change-password -H "Authorization: Bearer <access-token>" -d '{"current_password": "Oldpass123!", "new_password": "Newpass123!"}' -H "Content-Type: application/json"
   ```
5. **Check Database**:
   ```bash
   docker exec cedrina_postgres_1 psql -U postgres -d cedrina_dev -c "SELECT * FROM users"
   docker exec cedrina_postgres_1 psql -U postgres -d cedrina_dev -c "SELECT * FROM sessions"
   ```

6. **Check Redis**:
   ```bash
   docker exec cedrina_redis_1 redis-cli KEYS "refresh_token:*"
   ```

## Testing
Tests are in:
- **Unit Tests**: `tests/unit/services/auth/`
  - `test_user_authentication.py`
  - `test_oauth.py`
  - `test_token.py`
  - `test_session.py`
- **Integration Tests**: `tests/integration/services/auth/`
  - `test_auth_integration.py`
- **Exception Tests**: `tests/unit/core/test_exceptions.py`

Run tests:
```bash
poetry run pytest --cov=src/domain/services/auth --cov=src/core/exceptions --cov-report=html
```

View coverage:
```bash
open htmlcov/index.html
```

## Troubleshooting
- **AuthenticationError**:
  - Verify credentials, user status, token validity, or password policy compliance.
  - Check logs:
    ```bash
    docker logs cedrina_app_1
    ```
- **RateLimitError**:
  - Wait 60 seconds or clear Redis:
    ```bash
    docker exec cedrina_redis_1 redis-cli FLUSHDB
    ```
- **OAuth Failure**:
  - Verify client IDs/secrets in `.env.development`.
- **JWT Validation Failure**:
  - Check RSA keys, `JWT_ISSUER`, `JWT_AUDIENCE`, or token blacklisting status.
