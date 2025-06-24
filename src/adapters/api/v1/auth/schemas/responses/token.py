from __future__ import annotations

"""Response Pydantic model for token data."""

from pydantic import BaseModel


class TokenPair(BaseModel):
    """JWT access & refresh tokens with additional metadata."""

    access_token: str
    refresh_token: str
    token_type: str = "Bearer" 
    expires_in: int  # Access token expiration time in seconds 