import os
import gettext
from fastapi import Request
from src.core.config.settings import settings
from src.core.logging import logger

# Store translations for each language
_translations = {}

def setup_i18n():
    # Ensure absolute path for locales
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    locales_path = os.path.join(base_dir, "locales")
    try:
        # Verify locales path exists
        if not os.path.exists(locales_path):
            raise FileNotFoundError(f"Locales directory not found: {locales_path}")
        
        # Initialize gettext for each supported language
        for lang in settings.SUPPORTED_LANGUAGES:
            try:
                translation = gettext.translation(
                    domain="messages",
                    localedir=locales_path,
                    languages=[lang],
                    fallback=True
                )
                _translations[lang] = translation
                logger.info("i18n_initialized", language=lang, locales_path=locales_path)
            except Exception as e:
                logger.error("i18n_init_failed", language=lang, error=str(e))
        
        logger.info("i18n_setup_complete", default_locale=settings.DEFAULT_LANGUAGE)
    except Exception as e:
        logger.error("i18n_setup_failed", error=str(e))

def get_translated_message(key: str, locale: str = settings.DEFAULT_LANGUAGE) -> str:
    if locale not in settings.SUPPORTED_LANGUAGES:
        locale = settings.DEFAULT_LANGUAGE
    
    try:
        translation = _translations.get(locale)
        if translation is None:
            logger.error("translation_not_found_for_locale", locale=locale, available_translations=list(_translations.keys()))
            # Attempt to reload translations for the specific locale if setup failed generally
            # This is a fallback, ideally setup_i18n should succeed for all locales
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
            locales_path = os.path.join(base_dir, "locales")
            try:
                specific_translation = gettext.translation(
                    domain="messages",
                    localedir=locales_path,
                    languages=[locale],
                    fallback=True # Fallback to default if specific lang .mo not found
                )
                _translations[locale] = specific_translation
                translation = specific_translation
                logger.info("i18n_reinitialized_for_locale", language=locale)
            except Exception as ex:
                logger.error("i18n_reinit_failed_for_locale", language=locale, error=str(ex))
                return key # Return key if re-initialization also fails

        if translation is None: # Check again after attempting re-initialization
             logger.error("translation_still_not_found", locale=locale)
             return key

        translated = translation.gettext(key)
        # If gettext returns the key itself, it means translation was not found for that key
        if translated == key:
            logger.warning("translation_key_not_found", key=key, locale=locale)
        
        logger.debug("translation_fetched", key=key, locale=locale, result=translated)
        return translated
    except Exception as e:
        logger.error("translation_failed", key=key, locale=locale, error=str(e))
        return key  # Fallback to key if translation fails

def get_request_language(request: Request) -> str:
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