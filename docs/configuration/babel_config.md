# Babel Configuration Documentation for Cedrina

## Overview
Babel is a tool used in the `cedrina` project for internationalization (i18n), specifically to extract translatable strings from source code into translation templates. This document explains the purpose of the Babel configuration file, its contents, and how to customize it for managing translations.

## Babel Configuration File

### `babel.cfg`
- **What It Is**: The configuration file for Babel, defining how translatable strings are extracted from the codebase.
- **What It Does**: Specifies file types, directories, and keywords to scan for translatable strings, ensuring that all relevant text is captured for translation into supported languages (e.g., English, Persian, Arabic).
- **Key Contents**: 
  - Defines file patterns (e.g., `python_files = true` for Python files) to include in the extraction process.
  - Lists keywords for marking translatable strings (e.g., `_`, `gettext`) used in the code.
  - Configures output settings for the translation template file (`messages.pot`).
- **Location**: Project root directory.
- **How to Customize**: 
  1. Update file patterns or directories to include additional file types (e.g., Jinja2 templates with `jinja2 = true`) or exclude irrelevant paths (e.g., `ignore_dirs = venv, tests`).
  2. Add custom keywords if the project uses non-standard functions for marking translatable strings (e.g., `keywords = _ gettext mytranslate`).
  3. Adjust the output file or format if a different structure for `messages.pot` is needed.
- **Important Notes**: Customizations should be tested by running `pybabel extract` to ensure all translatable strings are captured without extraneous noise. Ensure alignment with the `locales/` directory structure for translation files.

## Customization Guidelines
- **Scope of Extraction**: Tailor `babel.cfg` to focus on relevant parts of the codebase. Exclude directories or files that don't contain user-facing text to reduce clutter in translation files.
- **Language Support**: Ensure keywords and file types match the project's i18n implementation, especially if using frameworks or libraries with specific translation mechanisms.
- **Version Control**: Commit `babel.cfg` to version control to maintain consistent extraction rules across the team.
- **Testing Changes**: After modifying `babel.cfg`, run `pybabel extract -F babel.cfg -o locales/messages.pot .` to generate a new template and verify that the expected strings are extracted.

## How to Use
1. Extract translatable strings with `pybabel extract -F babel.cfg -o locales/messages.pot .` to create or update the `messages.pot` template file in the `locales/` directory.
2. Initialize or update translation files for a specific language with `pybabel init -i locales/messages.pot -d locales -l <lang>` (e.g., `-l fa` for Persian) or `pybabel update` for existing languages.
3. Compile translations into binary format for runtime use with `pybabel compile -d locales` after editing `.po` files.
4. Integrate translations in the application by ensuring `utils/i18n.py` or similar modules load the compiled `.mo` files based on user language preference.

This documentation provides a clear understanding of Babel configuration in the `cedrina` project, enabling developers to manage internationalization and customize string extraction effectively. 