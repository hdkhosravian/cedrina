from __future__ import annotations

"""Miscellaneous utility schemas used by the auth API."""

from datetime import datetime, timezone
from pydantic import BaseModel, Field

class MessageResponse(BaseModel):
    """Simple envelope used for *200* or *202* acknowledgments."""

    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc)) 