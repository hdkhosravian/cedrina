import pytest
from unittest.mock import patch

from src.domain.entities.user import User


def test_email_confirmed_default_respects_feature_flag():
    with patch("src.core.config.settings.settings.EMAIL_CONFIRMATION_ENABLED", False):
        user = User()
        assert user.email_confirmed is True
    with patch("src.core.config.settings.settings.EMAIL_CONFIRMATION_ENABLED", True):
        user = User()
        assert user.email_confirmed is False
