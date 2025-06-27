from __future__ import annotations

"""Response Pydantic model for user data."""

from typing import List, Optional
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime, timezone

from src.domain.entities.user import Role, User


class UserOut(BaseModel):
    """Serialised representation of :class:`~src.domain.entities.user.User`."""

    id: int
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    is_active: bool = True
    created_at: datetime
    updated_at: Optional[datetime] = None
    roles: List[Role] = []

    @classmethod
    def from_entity(cls, user: User) -> 'UserOut':
        # Handle both singular role and list of roles
        roles = []
        if hasattr(user, 'roles') and user.roles:
            roles = user.roles
        elif hasattr(user, 'role') and user.role:
            roles = [user.role]
        # Handle None value for created_at
        created_at = user.created_at if user.created_at else datetime.now(timezone.utc)
        return cls(
            id=user.id,
            username=user.username,
            email=user.email,
            full_name=getattr(user, 'full_name', None),
            is_active=user.is_active,
            created_at=created_at,
            updated_at=user.updated_at,
            roles=roles
        )

    model_config = {
        "from_attributes": True
    } 