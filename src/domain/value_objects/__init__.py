"""Domain Value Objects for the authentication domain.

Value objects are immutable objects that describe domain concepts by their attributes
rather than their identity. They are essential building blocks in Domain-Driven Design.
"""

from .email import Email
from .email_confirmation_token import EmailConfirmationToken
from .jwt_token import TokenId, AccessToken, RefreshToken
from .oauth_provider import OAuthProvider
from .oauth_token import OAuthToken
from .oauth_user_info import OAuthUserInfo
from .password import Password, HashedPassword
from .rate_limit import RateLimitWindow
from .reset_token import ResetToken
from .username import Username

__all__ = [
    "Email",
    "EmailConfirmationToken",
    "TokenId",
    "AccessToken",
    "RefreshToken",
    "OAuthProvider",
    "OAuthToken",
    "OAuthUserInfo",
    "Password",
    "HashedPassword",
    "RateLimitWindow",
    "ResetToken",
    "Username",
] 