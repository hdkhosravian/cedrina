from typing import Optional

class AuthenticationError(Exception):
    """
    Exception raised for authentication-related errors.

    Attributes:
        message (str): Error message explaining the failure.
        code (str): Optional error code for internationalization or logging.
    """

    def __init__(self, message: str, code: Optional[str] = None):
        self.message = message
        self.code = code or "authentication_error"
        super().__init__(self.message)

class RateLimitError(Exception):
    """
    Exception raised when rate limits are exceeded.

    Attributes:
        message (str): Error message explaining the rate limit.
        code (str): Optional error code for internationalization or logging.
    """

    def __init__(self, message: str = "Rate limit exceeded", code: Optional[str] = None):
        self.message = message
        self.code = code or "rate_limit_exceeded"
        super().__init__(self.message)