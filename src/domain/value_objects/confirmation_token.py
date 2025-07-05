"""Confirmation token value object."""

from dataclasses import dataclass
import secrets
from typing import ClassVar


@dataclass(frozen=True)
class ConfirmationToken:
    """Represents an email confirmation token."""

    value: str

    LENGTH: ClassVar[int] = 64

    @classmethod
    def generate(cls) -> "ConfirmationToken":
        # Use 32 bytes of entropy (~256 bits) for strong unguessability
        token = secrets.token_hex(cls.LENGTH // 2)
        return cls(value=token)
