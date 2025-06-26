from __future__ import annotations

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
from typing import Dict, Optional
from fastapi import Request
from babel.support import Translations
from src.core.config.settings import settings
from src.core.logging import logger

# Store translations for each language
_translations: Dict[str, gettext.GNUTranslations] = {}

# ---------------------------------------------------------------------------
# Internal fallback catalog (parsed from *.po* files)
# ---------------------------------------------------------------------------

# In scenarios where the compiled *.mo* files are out of date (e.g. during local
# development or in CI pipelines where the Babel compilation step was skipped),
# newly-added translations would not be picked up by *gettext* and the call
# would simply return the original *msgid*.  To avoid shipping untranslated
# (and often user-visible) strings, we parse the corresponding *.po* files at
# startup and keep a lightweight in-memory catalogue as a secondary lookup.

_fallback_catalogs: Dict[str, Dict[str, str]] = {}

def setup_i18n() -> None:
    """
    Initialize the internationalization system by loading translations.

    Loads translation files for each supported language from the locales directory
    and parses .po files as a fallback for development environments where .mo
    files may not be updated. Logs initialization status for debugging.
    
    Raises:
        FileNotFoundError: If the locales directory is not found.
        Exception: For other initialization errors during .po file parsing.

    Performance:
        - Loads all translations into memory at startup, which may impact memory
          usage with many languages or large translation files.
        - Consider lazy loading or caching for scalability in future iterations.
    """
    # Ensure absolute path for locales
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    locales_path = os.path.join(base_dir, "locales")
    
    # Verify locales path exists
    if not os.path.exists(locales_path):
        raise FileNotFoundError(f"Locales directory not found: {locales_path}")
    
    # Initialize gettext and parse .po files for each supported language
    for lang in settings.SUPPORTED_LANGUAGES:
        translation = gettext.translation(
            domain="messages",
            localedir=locales_path,
            languages=[lang],
            fallback=True,
        )
        _translations[lang] = translation

        # Parse .po file as fallback for newly added translations not in .mo
        po_path = os.path.join(locales_path, lang, "LC_MESSAGES", "messages.po")
        catalog: Dict[str, str] = {}
        if os.path.exists(po_path):
            try:
                # Basic security: Limit file size to prevent memory exhaustion
                file_size = os.path.getsize(po_path)
                if file_size > 10 * 1024 * 1024:  # 10MB limit
                    logger.warning("i18n_po_file_too_large", lang=lang, size=file_size)
                    continue
                
                with open(po_path, "r", encoding="utf-8") as po_file:
                    current_msgid: Optional[str] = None
                    for raw_line in po_file:
                        line = raw_line.strip()
                        if line.startswith("msgid "):
                            current_msgid = line[6:].strip().strip('"')
                        elif line.startswith("msgstr ") and current_msgid is not None:
                            msgstr = line[7:].strip().strip('"')
                            catalog[current_msgid] = msgstr or current_msgid
                            current_msgid = None
            except Exception as exc:  # pragma: no cover
                logger.warning("i18n_po_parse_failed", lang=lang, error=str(exc))

        _fallback_catalogs[lang] = catalog
        logger.info("i18n_initialized", language=lang, entries=len(catalog))

    logger.info("i18n_setup_complete", default_locale=settings.DEFAULT_LANGUAGE)

def get_translated_message(key: str, locale: str = settings.DEFAULT_LANGUAGE) -> str:
    """
    Retrieve a translated message for the given key and locale.
    
    Validates the requested locale, attempts translation, and falls back to the
    default language or key if needed. Logs failures for debugging.
    
    Args:
        key: The message key to translate.
        locale: The target language code (defaults to DEFAULT_LANGUAGE).
        
    Returns:
        The translated message or the original key if translation fails.

    Security:
        - Validates locale against supported languages to prevent injection or
          unexpected behavior.
    """
    if locale not in _translations:
        logger.warning("unsupported_locale_requested", requested_locale=locale,
                       fallback_locale=settings.DEFAULT_LANGUAGE)
        locale = settings.DEFAULT_LANGUAGE
    
    translation = _translations.get(locale)
    if not translation:  # Safeguard if setup_i18n fails
        logger.error("translation_missing_for_locale", locale=locale)
        return key
        
    translated = translation.gettext(key)
    if translated == key:  # Translation not found in .mo
        catalog = _fallback_catalogs.get(locale, {})
        translated = catalog.get(key, key)
        if translated == key:
            logger.warning("translation_key_not_found", key=key, locale=locale)
    
    return translated

def get_request_language(request: Request) -> str:
    """
    Determine the preferred language from a request.
    
    Checks language preference in order: query parameter 'lang',
    Accept-Language header, then default language from settings.
    
    Args:
        request: The FastAPI request object.
        
    Returns:
        The determined language code.

    Security:
        - Validates language codes against supported languages to prevent
          unexpected behavior from malformed input.
    """
    # Check query parameter first
    lang = request.query_params.get("lang")
    if lang and lang in settings.SUPPORTED_LANGUAGES:
        return lang
    
    # Fallback to Accept-Language header
    accept_language = request.headers.get("Accept-Language",
                                          settings.DEFAULT_LANGUAGE)
    for lang in accept_language.split(","):
        lang = lang.split(";")[0].strip().split("-")[0]
        if lang in settings.SUPPORTED_LANGUAGES:
            return lang
    
    return settings.DEFAULT_LANGUAGE