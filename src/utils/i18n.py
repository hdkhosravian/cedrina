"""
Internationalization (i18n) utility module for handling translations and language preferences.

This module provides functionality for:
- Loading and managing translations for multiple languages
- Translating messages based on user preferences
- Determining user language from request headers or query parameters
- Fallback mechanisms for missing translations
- Logging of translation-related events

The module uses Python's built-in gettext for translation management and supports
multiple languages as configured in the application settings.
"""

import os
import gettext
import i18n
from fastapi import Request
from babel.support import Translations
from src.core.config.settings import settings
from src.core.logging import logger

# Store translations for each language
_translations = {}

def setup_i18n():
    """
    Initializes the internationalization system.
    
    This function:
    1. Locates the translations directory
    2. Loads translation files for each supported language
    3. Sets up fallback mechanisms
    4. Logs initialization status
    
    Raises:
        FileNotFoundError: If the locales directory is not found
        Exception: For other initialization errors
    """
    # Ensure absolute path for locales
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    locales_path = os.path.join(base_dir, "locales")
    # Verify locales path exists
    if not os.path.exists(locales_path):
        raise FileNotFoundError(f"Locales directory not found: {locales_path}")
    
    # Initialize gettext for each supported language
    for lang in settings.SUPPORTED_LANGUAGES:
        translation = gettext.translation(
            domain="messages",
            localedir=locales_path,
            languages=[lang],
            fallback=True
        )
        _translations[lang] = translation
        logger.info("i18n_initialized", language=lang, locales_path=locales_path)

    logger.info("i18n_setup_complete", default_locale=settings.DEFAULT_LANGUAGE)

def get_translated_message(key: str, locale: str = settings.DEFAULT_LANGUAGE) -> str:
    """
    Retrieves a translated message for the given key and locale.
    
    This function:
    1. Validates the requested locale
    2. Attempts to find the translation
    3. Falls back to default language if needed
    4. Handles missing translations gracefully
    5. Logs translation events
    
    Args:
        key (str): The message key to translate
        locale (str): The target language code (defaults to settings.DEFAULT_LANGUAGE)
        
    Returns:
        str: The translated message or the original key if translation fails
    """
    if locale not in _translations:
        logger.warning("unsupported_locale_requested", requested_locale=locale, fallback_locale=settings.DEFAULT_LANGUAGE)
        locale = settings.DEFAULT_LANGUAGE
    
    translation = _translations.get(locale)

    # This should not happen if setup_i18n is successful, but as a safeguard:
    if not translation:
        logger.error("translation_missing_for_locale", locale=locale)
        return key
        
    translated = translation.gettext(key)
    
    # If gettext returns the key itself, it means translation was not found for that key
    if translated == key:
        logger.warning("translation_key_not_found", key=key, locale=locale)
    
    return translated

def get_request_language(request: Request) -> str:
    """
    Determines the preferred language from the request.
    
    This function checks for language preference in the following order:
    1. Query parameter 'lang'
    2. Accept-Language header
    3. Default language from settings
    
    Args:
        request (Request): The FastAPI request object
        
    Returns:
        str: The determined language code
    """
    # Check query parameter first
    lang = request.query_params.get("lang")
    if lang and lang in settings.SUPPORTED_LANGUAGES:
        return lang
    # Fallback to Accept-Language header
    accept_language = request.headers.get("Accept-Language", settings.DEFAULT_LANGUAGE)
    for lang in accept_language.split(","):
        lang = lang.split(";")[0].strip().split("-")[0]
        if lang in settings.SUPPORTED_LANGUAGES:
            return lang
    return settings.DEFAULT_LANGUAGE