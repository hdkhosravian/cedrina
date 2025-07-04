"""A Value Object representing an email address in the domain.

This class encapsulates the properties and validation rules of an email address,
ensuring that any email in the domain is always in a valid state. As a Value
Object, it is immutable, and equality is based on its value (the email string),
not its identity.
"""

import re
from dataclasses import dataclass
from typing import ClassVar

from structlog import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Email:
    """An immutable, self-validating email address.

    This Value Object enforces several business rules upon instantiation:
    - Conforms to a standard email format (RFC 5322).
    - Has a reasonable length.
    - Is automatically normalized to lowercase.
    - Belongs to a non-disposable domain.

    Equality for `Email` objects is based on their string value.

    Attributes:
        value: The string representation of the email address.
    """

    value: str

    MAX_LENGTH: ClassVar[int] = 254
    MIN_LENGTH: ClassVar[int] = 5
    EMAIL_PATTERN: ClassVar[re.Pattern] = re.compile(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )
    BLOCKED_DOMAINS: ClassVar[set] = {
        "10minutemail.com",
        "tempmail.org",
        "guerrillamail.com",
        "mailinator.com",
        "yopmail.com",
        "throwaway.email",
        "temp-mail.org",
        "getnada.com",
        "fakeinbox.com",
        "maildrop.cc",
        "trashmail.com",
        "sharklasers.com",
    }

    def __post_init__(self):
        """Performs validation and normalization after initialization."""
        if not isinstance(self.value, str):
            raise TypeError("Email value must be a string.")

        normalized_value = self.value.strip().lower()
        object.__setattr__(self, "value", normalized_value)

        self._validate_length(normalized_value)
        self._validate_format(normalized_value)
        self._validate_domain(normalized_value)

        logger.debug("Email validated successfully", email=self.mask_for_logging())

    def _validate_length(self, value: str) -> None:
        """Validates the length of the email address."""
        if not (self.MIN_LENGTH <= len(value) <= self.MAX_LENGTH):
            raise ValueError(
                f"Email length must be between {self.MIN_LENGTH} and {self.MAX_LENGTH} characters."
            )

    def _validate_format(self, value: str) -> None:
        """Validates the format of the email address using a regex pattern."""
        if not self.EMAIL_PATTERN.match(value):
            raise ValueError("Invalid email format.")

    def _validate_domain(self, value: str) -> None:
        """Validates the domain part of the email address."""
        domain = value.split("@")[1]
        if domain in self.BLOCKED_DOMAINS:
            raise ValueError("Disposable email providers are not allowed.")

    @property
    def domain(self) -> str:
        """Returns the domain part of the email address."""
        return self.value.split("@")[1]

    @property
    def local_part(self) -> str:
        """Returns the local part of the email address (before the '@')."""
        return self.value.split("@")[0]

    def mask_for_logging(self) -> str:
        """Returns a masked version of the email for safe logging.

        Example: 'us**@e*****.com'
        """
        local, domain_part = self.value.split("@")
        masked_local = f"{local[:2]}{'*' * (len(local) - 2)}"
        masked_domain = f"{domain_part[:1]}{'*' * (len(domain_part) - 2)}{domain_part[-1:]}"
        return f"{masked_local}@{masked_domain}"

    def is_common_provider(self) -> bool:
        """Checks if the email is from a common public provider."""
        common_providers = {
            "gmail.com",
            "yahoo.com",
            "hotmail.com",
            "outlook.com",
            "icloud.com",
        }
        return self.domain in common_providers

    def __str__(self) -> str:
        """Returns the string representation of the email."""
        return self.value

    def __eq__(self, other: object) -> bool:
        """Compares two Email objects for equality."""
        if isinstance(other, Email):
            return self.value == other.value
        return False

    def __hash__(self) -> int:
        """Generates a hash for the Email object."""
        return hash(self.value) 