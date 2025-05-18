import pytest

from src.core.exceptions import AuthenticationError, RateLimitError

def test_authentication_error_default():
    # Arrange
    message = "Invalid credentials"
    code = "auth_failed"

    # Act
    error = AuthenticationError(message, code)

    # Assert
    assert error.message == message
    assert error.code == code
    assert str(error) == message

def test_authentication_error_no_code():
    # Arrange
    message = "Invalid credentials"

    # Act
    error = AuthenticationError(message)

    # Assert
    assert error.message == message
    assert error.code == "authentication_error"
    assert str(error) == message

def test_rate_limit_error_default():
    # Arrange
    message = "Too many requests"
    code = "rate_limit"

    # Act
    error = RateLimitError(message, code)

    # Assert
    assert error.message == message
    assert error.code == code
    assert str(error) == message

def test_rate_limit_error_no_code():
    # Arrange
    message = "Rate limit exceeded"

    # Act
    error = RateLimitError()

    # Assert
    assert error.message == message
    assert error.code == "rate_limit_exceeded"
    assert str(error) == message