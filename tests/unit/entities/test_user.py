import pytest

from src.domain.entities.user import User


@pytest.mark.unit
def test_validate_username_valid():
    """Test that a valid username passes validation."""
    username = "test_user-123"
    result = User.validate_username(username)
    assert result == username


@pytest.mark.unit
def test_validate_username_invalid_characters():
    """Test that a username with invalid characters raises a ValueError with translated message."""
    username = "test@user!"
    with pytest.raises(
        ValueError, match="Username must contain only letters, numbers, underscores, or hyphens"
    ):
        User.validate_username(username)


@pytest.mark.unit
def test_validate_username_lowercase_normalization():
    """Test that usernames are normalized to lowercase."""
    username = "Test_User-123"
    result = User.validate_username(username)
    assert result == "test_user-123"


@pytest.mark.unit
def test_validate_email_lowercase_normalization():
    """Test that emails are normalized to lowercase."""
    email = "Test@Example.com"
    result = User.validate_email(email)
    assert result == "test@example.com"
