import re
from src.core.exceptions import PasswordPolicyError

class PasswordPolicyValidator:
    """
    Validates passwords against a defined security policy.
    
    The policy requires passwords to meet minimum length, and include a mix of 
    uppercase letters, lowercase letters, numbers, and special characters.
    """
    def __init__(
        self,
        min_length: int = 8,
        require_uppercase: bool = True,
        require_lowercase: bool = True,
        require_digit: bool = True,
        require_special_char: bool = True,
    ):
        self.min_length = min_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_digit = require_digit
        self.require_special_char = require_special_char

    def validate(self, password: str):
        """
        Validates the given password against the policy.

        Args:
            password (str): The password to validate.

        Raises:
            PasswordPolicyError: If the password does not meet the policy requirements.
        """
        if len(password) < self.min_length:
            raise PasswordPolicyError(f"Password must be at least {self.min_length} characters long.")
        if self.require_uppercase and not re.search(r"[A-Z]", password):
            raise PasswordPolicyError("Password must contain at least one uppercase letter.")
        if self.require_lowercase and not re.search(r"[a-z]", password):
            raise PasswordPolicyError("Password must contain at least one lowercase letter.")
        if self.require_digit and not re.search(r"\d", password):
            raise PasswordPolicyError("Password must contain at least one digit.")
        if self.require_special_char and not re.search(r"[!@#$%^&*(),.?:{}|<>_=-]", password):
            raise PasswordPolicyError("Password must contain at least one special character.") 