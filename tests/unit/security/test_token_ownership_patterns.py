"""Security tests for token ownership validation patterns.

This module provides comprehensive tests that validate the security patterns
documented in docs/authentication/security_fixes.md. These tests serve as
both validation and examples for implementing secure token handling.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from jose import jwt

from src.core.config.settings import settings
from src.core.exceptions import AuthenticationError
from src.domain.entities.user import Role, User
from src.utils.i18n import get_translated_message


class TestTokenOwnershipValidationPattern:
    """Test suite for the standard token ownership validation pattern.

    These tests demonstrate the secure pattern for validating token ownership
    and provide examples for implementing similar validation in future endpoints.
    """

    @pytest.fixture
    def primary_user(self):
        """Primary user for testing token ownership."""
        return User(
            id=1,
            username="primary_user",
            email="primary@example.com",
            role=Role.USER,
            is_active=True,
        )

    @pytest.fixture
    def other_user(self):
        """Another user to test cross-user scenarios."""
        return User(
            id=2, username="other_user", email="other@example.com", role=Role.USER, is_active=True
        )

    def create_test_token(self, user: User, jti: str = "test-jti") -> str:
        """Helper to create valid JWT tokens for testing."""
        payload = {
            "sub": str(user.id),
            "jti": jti,
            "exp": datetime.now(timezone.utc) + timedelta(days=7),
            "iat": datetime.now(timezone.utc),
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
        }
        return jwt.encode(payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256")

    async def validate_token_ownership(
        self, token: str, current_user: User, language: str = "en"
    ) -> dict:
        """Reference implementation of the secure token ownership validation pattern.

        This method demonstrates the pattern documented in security_fixes.md
        and should be used as a template for implementing similar validation.
        """
        try:
            payload = jwt.decode(
                token,
                settings.JWT_PUBLIC_KEY,
                algorithms=["RS256"],
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE,
            )
            token_user_id = int(payload["sub"])

            # CRITICAL: Validate that token belongs to authenticated user
            if token_user_id != current_user.id:
                raise AuthenticationError(get_translated_message("invalid_token", language))

            return payload

        except Exception as e:
            raise AuthenticationError(get_translated_message("invalid_token", language)) from e

    @pytest.mark.asyncio
    async def test_valid_token_ownership_passes(self, primary_user):
        """SECURITY TEST: Valid token ownership should pass validation.

        Demonstrates correct usage of the token ownership validation pattern.
        """
        # Create token that belongs to primary_user
        token = self.create_test_token(primary_user)

        # Validate token ownership - should succeed
        payload = await self.validate_token_ownership(token, primary_user)

        assert payload["sub"] == str(primary_user.id)
        assert payload["jti"] == "test-jti"

    @pytest.mark.asyncio
    async def test_cross_user_token_rejected(self, primary_user, other_user):
        """SECURITY TEST: Cross-user token usage should be rejected.

        This is the critical security test that prevents the vulnerability
        we fixed in the logout endpoint.
        """
        # Create token that belongs to other_user
        other_user_token = self.create_test_token(other_user)

        # Try to validate as primary_user - should fail
        with pytest.raises(AuthenticationError, match="Invalid token"):
            await self.validate_token_ownership(other_user_token, primary_user)

    @pytest.mark.asyncio
    async def test_malformed_token_rejected(self, primary_user):
        """SECURITY TEST: Malformed tokens should be rejected.

        Tests the JWT validation and error handling aspects of the pattern.
        """
        malformed_token = "not.a.valid.jwt.token"

        with pytest.raises(AuthenticationError, match="Invalid token"):
            await self.validate_token_ownership(malformed_token, primary_user)

    @pytest.mark.asyncio
    async def test_expired_token_rejected(self, primary_user):
        """SECURITY TEST: Expired tokens should be rejected.

        Tests temporal validation in the security pattern.
        """
        # Create expired token
        payload = {
            "sub": str(primary_user.id),
            "jti": "expired-jti",
            "exp": datetime.now(timezone.utc) - timedelta(days=1),  # Expired
            "iat": datetime.now(timezone.utc) - timedelta(days=8),
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
        }
        expired_token = jwt.encode(
            payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256"
        )

        with pytest.raises(AuthenticationError, match="Invalid token"):
            await self.validate_token_ownership(expired_token, primary_user)

    @pytest.mark.asyncio
    async def test_invalid_issuer_rejected(self, primary_user):
        """SECURITY TEST: Tokens with wrong issuer should be rejected.

        Tests issuer validation in the JWT security pattern.
        """
        # Create token with wrong issuer
        payload = {
            "sub": str(primary_user.id),
            "jti": "wrong-issuer-jti",
            "exp": datetime.now(timezone.utc) + timedelta(days=7),
            "iat": datetime.now(timezone.utc),
            "iss": "https://malicious-issuer.com",  # Wrong issuer
            "aud": settings.JWT_AUDIENCE,
        }
        wrong_issuer_token = jwt.encode(
            payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256"
        )

        with pytest.raises(AuthenticationError, match="Invalid token"):
            await self.validate_token_ownership(wrong_issuer_token, primary_user)

    @pytest.mark.asyncio
    async def test_invalid_audience_rejected(self, primary_user):
        """SECURITY TEST: Tokens with wrong audience should be rejected.

        Tests audience validation in the JWT security pattern.
        """
        # Create token with wrong audience
        payload = {
            "sub": str(primary_user.id),
            "jti": "wrong-audience-jti",
            "exp": datetime.now(timezone.utc) + timedelta(days=7),
            "iat": datetime.now(timezone.utc),
            "iss": settings.JWT_ISSUER,
            "aud": "wrong-audience",  # Wrong audience
        }
        wrong_audience_token = jwt.encode(
            payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256"
        )

        with pytest.raises(AuthenticationError, match="Invalid token"):
            await self.validate_token_ownership(wrong_audience_token, primary_user)


class TestSecureEndpointPatterns:
    """Test suite demonstrating secure vs insecure endpoint implementation patterns.

    These tests show the difference between secure and vulnerable patterns
    for implementing token-handling endpoints.
    """

    @pytest.fixture
    def user_one(self):
        return User(
            id=1, username="user_one", email="one@example.com", role=Role.USER, is_active=True
        )

    @pytest.fixture
    def user_two(self):
        return User(
            id=2, username="user_two", email="two@example.com", role=Role.USER, is_active=True
        )

    @pytest.fixture
    def mock_token_service(self):
        """Mock token service for testing endpoint patterns."""
        service = AsyncMock()
        service.refresh_tokens = AsyncMock()
        return service

    def create_refresh_token(self, user: User) -> str:
        """Helper to create refresh tokens for testing."""
        payload = {
            "sub": str(user.id),
            "jti": f"refresh-{user.id}",
            "exp": datetime.now(timezone.utc) + timedelta(days=7),
            "iat": datetime.now(timezone.utc),
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
        }
        return jwt.encode(payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256")

    async def secure_refresh_endpoint(self, refresh_token: str, token_service):
        """SECURE PATTERN: Extract user from token itself.

        This pattern is inherently secure because the user ID comes from
        the token being refreshed, not from external authentication.
        """
        # This delegates to TokenService.refresh_tokens which is secure
        return await token_service.refresh_tokens(refresh_token)

    async def vulnerable_refresh_endpoint(
        self, refresh_token: str, current_user: User, token_service
    ):
        """VULNERABLE PATTERN: Using current_user creates attack vector.

        This pattern is vulnerable because it trusts the current_user
        rather than validating the token belongs to that user.
        """
        # ❌ VULNERABLE: This would allow cross-user attacks
        # DON'T DO THIS - it's shown here only for testing purposes

        # Simulate vulnerable logic that doesn't validate ownership
        # In a real vulnerable implementation, this might:
        # 1. Use current_user.id to lookup sessions
        # 2. Accept any valid refresh token without ownership checks
        # 3. Return tokens for current_user regardless of token ownership

        # For testing, we'll decode the token but not validate ownership
        try:
            payload = jwt.decode(
                refresh_token,
                settings.JWT_PUBLIC_KEY,
                algorithms=["RS256"],
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE,
            )
            # ❌ VULNERABILITY: Not checking if payload["sub"] == current_user.id
            return await token_service.refresh_tokens(refresh_token)
        except Exception:
            raise AuthenticationError("Invalid token")

    @pytest.mark.asyncio
    async def test_secure_pattern_prevents_cross_user_attack(
        self, user_one, user_two, mock_token_service
    ):
        """SECURITY TEST: Secure pattern should prevent cross-user attacks.

        The secure pattern delegates to TokenService.refresh_tokens which
        validates ownership internally.
        """
        # Create token for user_two
        user_two_token = self.create_refresh_token(user_two)

        # Configure mock to raise error for cross-user attempt
        mock_token_service.refresh_tokens.side_effect = AuthenticationError("Invalid refresh token")

        # Attempt to use secure endpoint - should fail safely
        with pytest.raises(AuthenticationError):
            await self.secure_refresh_endpoint(user_two_token, mock_token_service)

        # Verify the token service was called with the actual token
        mock_token_service.refresh_tokens.assert_called_once_with(user_two_token)

    @pytest.mark.asyncio
    async def test_secure_pattern_allows_legitimate_use(self, user_one, mock_token_service):
        """SECURITY TEST: Secure pattern should allow legitimate usage.

        Users should be able to refresh their own tokens.
        """
        # Create token for user_one
        user_one_token = self.create_refresh_token(user_one)

        # Configure mock for successful refresh
        mock_token_service.refresh_tokens.return_value = {
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "token_type": "bearer",
            "expires_in": 900,
        }

        # Use secure endpoint - should succeed
        result = await self.secure_refresh_endpoint(user_one_token, mock_token_service)

        assert result["access_token"] == "new_access_token"
        mock_token_service.refresh_tokens.assert_called_once_with(user_one_token)

    @pytest.mark.asyncio
    async def test_vulnerable_pattern_demonstration(self, user_one, user_two, mock_token_service):
        """SECURITY TEST: Demonstrates why the vulnerable pattern is dangerous.

        This test shows what could happen with a vulnerable implementation.
        The vulnerable pattern is shown for educational purposes only.
        """
        # Create token for user_two
        user_two_token = self.create_refresh_token(user_two)

        # Configure mock to simulate successful token refresh
        mock_token_service.refresh_tokens.return_value = {
            "access_token": "hijacked_access_token",
            "refresh_token": "hijacked_refresh_token",
            "token_type": "bearer",
            "expires_in": 900,
        }

        # In a vulnerable implementation, this would succeed
        # allowing user_one to refresh user_two's token
        result = await self.vulnerable_refresh_endpoint(
            user_two_token, user_one, mock_token_service
        )

        # This demonstrates the vulnerability - user_one got tokens
        # using user_two's refresh token
        assert result["access_token"] == "hijacked_access_token"


class TestExistingServiceSecurity:
    """Test suite validating that existing services maintain security patterns.

    These tests ensure our current TokenService and SessionService maintain
    proper security and can serve as examples for future implementations.
    """

    @pytest.fixture
    def mock_db_session(self):
        return AsyncMock()

    @pytest.fixture
    def mock_redis_client(self):
        return AsyncMock()

    @pytest.fixture
    def mock_session_service(self):
        service = AsyncMock()
        service.get_session = AsyncMock()
        service.revoke_session = AsyncMock()
        return service

    @pytest.mark.asyncio
    async def test_token_service_refresh_tokens_validates_ownership(
        self, mock_db_session, mock_redis_client, mock_session_service
    ):
        """SECURITY TEST: TokenService.refresh_tokens should validate ownership.

        This test confirms that the existing refresh_tokens method follows
        secure patterns by extracting user ID from the token itself.
        """
        import hashlib

        from src.domain.entities.session import Session
        from src.infrastructure.services.authentication.token import TokenService

        # Create test users
        user_one = User(
            id=1, username="user_one", email="one@example.com", role=Role.USER, is_active=True
        )
        user_two = User(
            id=2, username="user_two", email="two@example.com", role=Role.USER, is_active=True
        )

        # Create token for user_two
        user_two_token = jwt.encode(
            {
                "sub": str(user_two.id),
                "jti": "user-two-jti",
                "exp": datetime.now(timezone.utc) + timedelta(days=7),
                "iat": datetime.now(timezone.utc),
                "iss": settings.JWT_ISSUER,
                "aud": settings.JWT_AUDIENCE,
            },
            settings.JWT_PRIVATE_KEY.get_secret_value(),
            algorithm="RS256",
        )

        # Create correct hash for the token
        token_hash = hashlib.sha256(user_two_token.encode()).hexdigest()

        # Mock Redis to return valid hash
        mock_redis_client.get.return_value = token_hash.encode()

        # Mock enhanced session validation methods
        mock_session_service.is_session_valid = AsyncMock(return_value=True)
        mock_session_service.update_session_activity = AsyncMock(return_value=True)
        mock_session_service.revoke_session = AsyncMock(return_value=None)

        # Mock database to return user_two
        mock_db_session.get.return_value = user_two

        # Create TokenService
        token_service = TokenService(mock_db_session, mock_redis_client, mock_session_service)

        # The service should validate that token belongs to user_two
        # It extracts user_id from token and validates session belongs to that user
        result = await token_service.refresh_tokens(user_two_token)

        # Verify it called enhanced session validation methods with user_two's ID (from token)
        mock_session_service.is_session_valid.assert_called_once_with("user-two-jti", user_two.id)
        mock_session_service.update_session_activity.assert_called_once_with("user-two-jti", user_two.id)

        # Verify it retrieved user_two from database
        mock_db_session.get.assert_called_once_with(User, user_two.id)

        assert "access_token" in result
        assert "refresh_token" in result

    @pytest.mark.asyncio
    async def test_session_service_revoke_token_validates_ownership(
        self, mock_db_session, mock_redis_client
    ):
        """SECURITY TEST: SessionService.revoke_token should validate ownership.

        This test confirms that the existing revoke_token method follows
        secure patterns by extracting user ID from the token itself.
        """
        from unittest.mock import MagicMock

        from src.domain.entities.session import Session
        from src.infrastructure.services.authentication.session import SessionService

        # Create test user
        user = User(
            id=1, username="test_user", email="test@example.com", role=Role.USER, is_active=True
        )

        # Create token for user
        token = jwt.encode(
            {
                "sub": str(user.id),
                "jti": "test-jti",
                "exp": datetime.now(timezone.utc) + timedelta(days=7),
                "iat": datetime.now(timezone.utc),
                "iss": settings.JWT_ISSUER,
                "aud": settings.JWT_AUDIENCE,
            },
            settings.JWT_PRIVATE_KEY.get_secret_value(),
            algorithm="RS256",
        )

        # Mock session lookup - properly mock async call
        session = Session(user_id=user.id, jti="test-jti", refresh_token_hash="hash")

        # Mock the async get_session method
        session_service = SessionService(mock_db_session, mock_redis_client)
        session_service.get_session = AsyncMock(return_value=session)

        # Mock the synchronous add method (not async)
        mock_db_session.add = MagicMock()

        # The service should extract user_id from token and validate session
        await session_service.revoke_token(token)

        # Verify it called get_session with the correct parameters
        session_service.get_session.assert_called_once_with("test-jti", user.id)

        # Verify it updated the session revoked_at timestamp
        assert session.revoked_at is not None
        mock_db_session.add.assert_called_once_with(session)
        mock_db_session.commit.assert_called_once()
