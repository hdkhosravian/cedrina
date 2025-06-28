"""Export authentication-related domain entities for use across the application.

This module provides a clean interface for importing User, OAuthProfile, and Session
models, ensuring modularity and adherence to DDD principles.
"""

from .oauth_profile import OAuthProfile, Provider
from .session import Session
from .user import Role, User

__all__ = ["User", "Role", "OAuthProfile", "Provider", "Session"]
