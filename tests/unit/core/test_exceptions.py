import pytest
from src.core.exceptions import AuthenticationError, RateLimitError
from src.utils.i18n import get_translated_message

def test_authentication_error_default():
    # Arrange
    message = get_translated_message("invalid_credentials", "en")
    code = "auth_failed"

    # Act
    error = AuthenticationError(message, code)

    # Assert
    assert error.message == message
    assert error.code == code
    assert str(error) == message

def test_authentication_error_no_code():
    # Arrange
    message = get_translated_message("invalid_credentials", "en")

    # Act
    error = AuthenticationError(message)

    # Assert
    assert error.message == message
    assert error.code == "authentication_error"
    assert str(error) == message

def test_rate_limit_error_default():
    # Arrange
    message = get_translated_message("too_many_requests", "en")
    code = "rate_limit"

    # Act
    error = RateLimitError(message, code)

    # Assert
    assert error.message == message
    assert error.code == code
    assert str(error) == message

def test_rate_limit_error_no_code():
    # Arrange
    message = get_translated_message("rate_limit_exceeded", "en")

    # Act
    error = RateLimitError()

    # Assert
    assert error.message == message
    assert error.code == "rate_limit_exceeded"
    assert str(error) == message