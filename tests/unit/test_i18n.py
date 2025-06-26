import pytest
from fastapi import Request
from unittest.mock import MagicMock
import os
import gettext

from core.config.settings import settings
from utils.i18n import setup_i18n, get_translated_message, get_request_language, _translations


def test_setup_i18n_success(mocker):
    """Test successful setup of i18n translations."""
    mocker.patch('os.path.exists', return_value=True)
    mock_translation = mocker.MagicMock()
    mocker.patch('gettext.translation', return_value=mock_translation)
    mocker.patch('core.logging.logger.info')
    mocker.patch('core.logging.logger.error')
    
    setup_i18n()
    
    assert len(_translations) == len(settings.SUPPORTED_LANGUAGES)
    for lang in settings.SUPPORTED_LANGUAGES:
        assert lang in _translations


def test_setup_i18n_locales_not_found(mocker):
    """Test setup_i18n when locales directory is not found."""
    mocker.patch('os.path.exists', return_value=False)
    
    with pytest.raises(FileNotFoundError):
        setup_i18n()


def test_setup_i18n_translation_error(mocker):
    """Test setup_i18n when translation loading fails for a language."""
    mocker.patch('os.path.exists', return_value=True)
    mocker.patch('gettext.translation', side_effect=Exception("Translation loading failed"))
    
    with pytest.raises(Exception, match="Translation loading failed"):
        setup_i18n()


def test_get_translated_message_success(mocker):
    """Test successful retrieval of a translated message."""
    mock_translation = mocker.MagicMock()
    mock_translation.gettext.return_value = "Translated text"
    _translations[settings.DEFAULT_LANGUAGE] = mock_translation
    
    result = get_translated_message("test_key", settings.DEFAULT_LANGUAGE)
    assert result == "Translated text"
    mock_translation.gettext.assert_called_once_with("test_key")


def test_get_translated_message_invalid_locale(mocker):
    """Test translation retrieval with an invalid locale, should fallback to default."""
    mock_translation = mocker.MagicMock()
    mock_translation.gettext.return_value = "Translated text"
    _translations[settings.DEFAULT_LANGUAGE] = mock_translation
    
    result = get_translated_message("test_key", "invalid_locale")
    assert result == "Translated text"
    mock_translation.gettext.assert_called_once_with("test_key")


def test_get_translated_message_not_found(mocker):
    """Test translation returns the key when the translation is missing."""
    mock_translation = mocker.MagicMock()
    # Simulate gettext behavior for a missing key
    mock_translation.gettext.side_effect = lambda key: key
    
    _translations['en'] = mock_translation
    
    mock_logger = mocker.patch('utils.i18n.logger')

    result = get_translated_message("untranslated_key", "en")
    
    assert result == "untranslated_key"
    mock_logger.warning.assert_called_with(
        "translation_key_not_found", 
        key="untranslated_key", 
        locale="en"
    )


def test_get_request_language_query_param(mocker):
    """Test language detection from query parameter."""
    mock_request = mocker.MagicMock(spec=Request)
    mock_request.query_params.get.return_value = "fa"
    mock_request.headers.get.return_value = "en-US,fa-IR"
    
    result = get_request_language(mock_request)
    assert result == "fa"


def test_get_request_language_header(mocker):
    """Test language detection from Accept-Language header."""
    mock_request = mocker.MagicMock(spec=Request)
    mock_request.query_params.get.return_value = None
    mock_request.headers.get.return_value = "fa-IR,en-US"
    
    result = get_request_language(mock_request)
    assert result == "fa"


def test_get_request_language_default(mocker):
    """Test language detection fallback to default language."""
    mock_request = mocker.MagicMock(spec=Request)
    mock_request.query_params.get.return_value = None
    mock_request.headers.get.return_value = "de-DE,fr-FR"
    
    result = get_request_language(mock_request)
    assert result == settings.DEFAULT_LANGUAGE 