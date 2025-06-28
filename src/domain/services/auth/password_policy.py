import re

from src.core.config.settings import (
    PASSWORD_MIN_LENGTH,
    PASSWORD_REQUIRE_DIGIT,
    PASSWORD_REQUIRE_LOWERCASE,
    PASSWORD_REQUIRE_SPECIAL_CHAR,
    PASSWORD_REQUIRE_UPPERCASE,
)
from src.core.exceptions import PasswordPolicyError
from src.utils.i18n import get_translated_message


class PasswordPolicyValidator:
    """Validates passwords against a defined security policy.

    The policy requires passwords to meet minimum length, and include a mix of
    uppercase letters, lowercase letters, numbers, and special characters.
    """

    def __init__(self):
        self.min_length = PASSWORD_MIN_LENGTH
        self.require_uppercase = PASSWORD_REQUIRE_UPPERCASE
        self.require_lowercase = PASSWORD_REQUIRE_LOWERCASE
        self.require_digit = PASSWORD_REQUIRE_DIGIT
        self.require_special_char = PASSWORD_REQUIRE_SPECIAL_CHAR

    def validate(self, password: str):
        """Validates the given password against the policy.

        Args:
            password (str): The password to validate.

        Raises:
            PasswordPolicyError: If the password does not meet the policy requirements.

        """
        if len(password) < self.min_length:
            raw = get_translated_message("password_too_short", "en")
            message = raw.format(length=self.min_length) if "{length}" in raw else raw
            raise PasswordPolicyError(message)

        if self.require_uppercase and not re.search(r"[A-Z]", password):
            raise PasswordPolicyError(get_translated_message("password_no_uppercase", "en"))

        if self.require_lowercase and not re.search(r"[a-z]", password):
            raise PasswordPolicyError(get_translated_message("password_no_lowercase", "en"))

        if self.require_digit and not re.search(r"\d", password):
            raise PasswordPolicyError(get_translated_message("password_no_digit", "en"))

        if self.require_special_char and not re.search(r"[!@#$%^&*(),.?:{}|<>_=-]", password):
            raise PasswordPolicyError(get_translated_message("password_no_special_char", "en"))
