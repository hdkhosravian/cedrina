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

# ---------------------------------------------------------------------------
# Internal fallback catalog (parsed from *.po* files)
# ---------------------------------------------------------------------------

# In scenarios where the compiled *.mo* files are out of date (e.g. during local
# development or in CI pipelines where the Babel compilation step was skipped),
# newly-added translations would not be picked up by *gettext* and the call
# would simply return the original *msgid*.  To avoid shipping untranslated
# (and often user-visible) strings, we parse the corresponding *.po* files at
# startup and keep a lightweight in-memory catalogue as a secondary lookup.

_fallback_catalogs: dict[str, dict[str, str]] = {}

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
    
    # Initialise gettext and parse *.po* files for each supported language
    for lang in settings.SUPPORTED_LANGUAGES:
        translation = gettext.translation(
            domain="messages",
            localedir=locales_path,
            languages=[lang],
            fallback=True,
        )
        _translations[lang] = translation

        # -------------------------------------------------------------------
        # Parse *.po* file for the language – this allows us to serve newly
        # added translations even when the compiled *.mo* file has not yet
        # been regenerated.  The parser is intentionally simple and only
        # supports the subset of the PO specification required for our use
        # case (single-line *msgid* / *msgstr* pairs).
        # -------------------------------------------------------------------
        po_path = os.path.join(locales_path, lang, "LC_MESSAGES", "messages.po")
        catalog: dict[str, str] = {}
        if os.path.exists(po_path):
            try:
                with open(po_path, "r", encoding="utf-8") as po_file:
                    current_msgid: str | None = None
                    for raw_line in po_file:
                        line = raw_line.strip()
                        if line.startswith("msgid "):
                            current_msgid = line[6:].strip().strip('"')
                        elif line.startswith("msgstr ") and current_msgid is not None:
                            msgstr = line[7:].strip().strip('"')
                            catalog[current_msgid] = msgstr or current_msgid
                            current_msgid = None
            except Exception as exc:  # pragma: no cover – defensive logging
                logger.warning("i18n_po_parse_failed", lang=lang, error=str(exc))

        _fallback_catalogs[lang] = catalog
        logger.info("i18n_initialized", language=lang, entries=len(catalog))

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
    
    if translated == key:
        # Attempt fallback catalog (parsed from *.po*)
        catalog = _fallback_catalogs.get(locale, {})
        translated = catalog.get(key, key)
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