"""Token Service Adapter for Clean Architecture Integration.

This adapter bridges the existing token service with our clean architecture,
allowing gradual migration while maintaining compatibility.
"""

from typing import Dict, Optional

import structlog

from src.domain.entities.user import User
from src.domain.interfaces.services import ITokenService
from src.infrastructure.services.authentication.token import TokenService as LegacyTokenService

logger = structlog.get_logger(__name__)


class TokenServiceAdapter(ITokenService):
    """Adapter that wraps the legacy token service for clean architecture.
    
    This adapter allows us to use the existing token service implementation
    while conforming to our new clean architecture interfaces. This enables
    gradual migration without breaking existing functionality.
    
    Benefits:
    - Maintains compatibility with existing code
    - Enables clean architecture adoption
    - Provides single responsibility interface
    - Allows gradual migration path
    """
    
    def __init__(self, legacy_token_service: LegacyTokenService):
        """Initialize adapter with legacy token service.
        
        Args:
            legacy_token_service: Existing token service implementation
        """
        self._legacy_service = legacy_token_service
        logger.info("TokenServiceAdapter initialized")
    
    async def create_access_token(self, user: User) -> str:
        """Create JWT access token for user.
        
        Args:
            user: User to create token for
            
        Returns:
            str: Encoded access token
        """
        try:
            # Delegate to legacy service
            token = await self._legacy_service.create_access_token(user)
            
            logger.debug(
                "Access token created via adapter",
                user_id=user.id,
                username=user.username[:3] + "***" if user.username else "Unknown",
            )
            
            return token
            
        except Exception as e:
            logger.error(
                "Failed to create access token via adapter",
                user_id=user.id,
                error=str(e),
            )
            raise
    
    async def create_refresh_token(self, user: User) -> str:
        """Create JWT refresh token for user.
        
        Args:
            user: User to create token for
            
        Returns:
            str: Encoded refresh token
        """
        try:
            # Delegate to legacy service
            token = await self._legacy_service.create_refresh_token(user)
            
            logger.debug(
                "Refresh token created via adapter",
                user_id=user.id,
                username=user.username[:3] + "***" if user.username else "Unknown",
            )
            
            return token
            
        except Exception as e:
            logger.error(
                "Failed to create refresh token via adapter",
                user_id=user.id,
                error=str(e),
            )
            raise
    
    async def refresh_tokens(self, refresh_token: str, language: str = "en") -> Dict[str, str]:
        """Refresh access and refresh tokens.
        
        Args:
            refresh_token: Current refresh token
            language: Language for error messages
            
        Returns:
            dict: New access and refresh tokens
            
        Raises:
            AuthenticationError: If refresh token is invalid or expired
        """
        try:
            # Delegate to legacy service
            tokens = await self._legacy_service.refresh_tokens(refresh_token, language)
            
            logger.debug(
                "Tokens refreshed via adapter",
                token_type=tokens.get("token_type", "unknown"),
            )
            
            return tokens
            
        except Exception as e:
            logger.error(
                "Failed to refresh tokens via adapter",
                error=str(e),
            )
            raise
    
    async def validate_access_token(self, token: str, language: str = "en") -> Dict[str, any]:
        """Validate access token and return claims.
        
        Args:
            token: Access token to validate
            language: Language for error messages
            
        Returns:
            dict: Token claims if valid
            
        Raises:
            AuthenticationError: If token is invalid or expired
        """
        try:
            # Delegate to legacy service
            claims = await self._legacy_service.validate_token(token, language)
            
            logger.debug(
                "Access token validated via adapter",
                user_id=claims.get("sub"),
                token_prefix=token[:10] + "***" if token else "None",
            )
            
            return claims
            
        except Exception as e:
            logger.error(
                "Failed to validate access token via adapter",
                token_prefix=token[:10] + "***" if token else "None",
                error=str(e),
            )
            raise
    
    async def revoke_refresh_token(self, token: str, language: str = "en") -> None:
        """Revoke refresh token.
        
        Args:
            token: Refresh token to revoke
            language: Language for error messages
        """
        try:
            # Delegate to legacy service
            await self._legacy_service.revoke_refresh_token(token, language)
            
            logger.debug(
                "Refresh token revoked via adapter",
                token_prefix=token[:10] + "***" if token else "None",
            )
            
        except Exception as e:
            logger.error(
                "Failed to revoke refresh token via adapter",
                token_prefix=token[:10] + "***" if token else "None",
                error=str(e),
            )
            raise

    async def revoke_access_token(self, jti: str, expires_in: int | None = None) -> None:
        """Revoke access token by blacklisting it.
        
        Args:
            jti: JWT ID to blacklist
            expires_in: Optional expiration time for blacklist entry
        """
        try:
            # Delegate to legacy service
            await self._legacy_service.revoke_access_token(jti, expires_in)
            
            logger.debug(
                "Access token revoked via adapter",
                jti=jti[:8] + "***" if jti else "None",
            )
            
        except Exception as e:
            logger.error(
                "Failed to revoke access token via adapter",
                jti=jti[:8] + "***" if jti else "None",
                error=str(e),
            )
            raise

    async def validate_token(self, token: str, language: str = "en") -> dict:
        """Validate JWT token.
        
        Args:
            token: JWT token to validate
            language: Language code for error messages
            
        Returns:
            dict: Token payload if valid
            
        Raises:
            AuthenticationError: If token is invalid
        """
        try:
            # Delegate to legacy service
            claims = await self._legacy_service.validate_token(token, language)
            
            logger.debug(
                "Token validated via adapter",
                user_id=claims.get("sub"),
                token_prefix=token[:10] + "***" if token else "None",
            )
            
            return claims
            
        except Exception as e:
            logger.error(
                "Failed to validate token via adapter",
                token_prefix=token[:10] + "***" if token else "None",
                error=str(e),
            )
            raise

    # Additional adapter methods for backwards compatibility
    
    async def create_token_pair(self, user: User) -> Dict[str, str]:
        """Create both access and refresh tokens for user.
        
        This is a convenience method that creates both tokens at once,
        commonly needed by authentication endpoints.
        
        Args:
            user: User to create tokens for
            
        Returns:
            dict: Both access and refresh tokens with metadata
        """
        try:
            # Create both tokens
            access_token = await self.create_access_token(user)
            refresh_token = await self.create_refresh_token(user)
            
            # Return in format expected by API endpoints
            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": 900,  # 15 minutes default for access token
            }
            
        except Exception as e:
            logger.error(
                "Failed to create token pair via adapter",
                user_id=user.id,
                error=str(e),
            )
            raise 