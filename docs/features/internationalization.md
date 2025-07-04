# Internationalization (i18n)

Cedrina provides comprehensive internationalization support using gettext and message catalogs. All user-facing strings, error messages, and responses can be translated into multiple languages.

## Overview

The i18n system in Cedrina follows these principles:

- **Language Detection**: Automatically detects language from `Accept-Language` header or user preferences
- **Fallback Support**: Falls back to English if translation is missing
- **Context-Aware**: Supports different translations based on context
- **Performance Optimized**: Uses compiled `.mo` files for fast lookups
- **Developer Friendly**: Clear separation between code and translations

## Supported Languages

Currently supported languages:
- **English (en)** - Default language
- **Arabic (ar)** - Right-to-left support
- **Spanish (es)** - Latin American and European variants
- **Persian (fa)** - Right-to-left support

## Architecture

### File Structure

```
locales/
├── messages.pot          # Template file with all translatable strings
├── en/
│   └── LC_MESSAGES/
│       ├── messages.po   # English translations
│       └── messages.mo   # Compiled English translations
├── ar/
│   └── LC_MESSAGES/
│       ├── messages.po   # Arabic translations
│       └── messages.mo   # Compiled Arabic translations
├── es/
│   └── LC_MESSAGES/
│       ├── messages.po   # Spanish translations
│       └── messages.mo   # Compiled Spanish translations
└── fa/
    └── LC_MESSAGES/
        ├── messages.po   # Persian translations
        └── messages.mo   # Compiled Persian translations
```

### Core Components

#### Translation Utilities (`src/utils/i18n.py`)

```python
from src.utils.i18n import (
    get_translated_message,
    get_request_language,
    setup_i18n,
    translate_error_message
)

# Get translated message
message = get_translated_message("user_registered_successfully", "en")

# Get language from request
language = get_request_language(request)

# Setup i18n system
setup_i18n()
```

#### Middleware Integration

The language middleware automatically:
1. Extracts language from `Accept-Language` header
2. Sets the language for the current request
3. Adds `Content-Language` header to responses

```python
# Language middleware automatically handles this
async def set_language_middleware(request: Request, call_next):
    lang = get_request_language(request)
    i18n.set("locale", lang)
    request.state.language = lang
    response = await call_next(request)
    response.headers["Content-Language"] = lang
    return response
```

## Usage Examples

### In Domain Services

```python
from src.utils.i18n import get_translated_message

class UserAuthenticationService:
    async def authenticate_user(self, username: str, password: str, language: str = "en"):
        try:
            # Authentication logic
            pass
        except AuthenticationError:
            error_message = get_translated_message("invalid_credentials", language)
            raise AuthenticationError(message=error_message)
```

### In API Endpoints

```python
from src.utils.i18n import get_request_language, get_translated_message

@router.post("/login")
async def login(request: Request, payload: LoginRequest):
    language = get_request_language(request)
    
    try:
        # Authentication logic
        success_message = get_translated_message("login_successful", language)
        return {"message": success_message}
    except AuthenticationError:
        error_message = get_translated_message("login_failed", language)
        raise HTTPException(status_code=401, detail=error_message)
```

### In Error Handling

```python
from src.domain.security.error_standardization import error_standardization_service

# Standardized error responses with i18n
standardized_response = await error_standardization_service.create_standardized_response(
    error_type="invalid_input",
    actual_error=str(e),
    correlation_id=correlation_id,
    language=language
)
```

## Message Catalog Management

### Adding New Messages

1. **Add the message to the template**:
   ```bash
   # Extract all translatable strings
   pybabel extract -F babel.cfg -k _l -o locales/messages.pot .
   ```

2. **Update existing language files**:
   ```bash
   # Update English translations
   pybabel update -i locales/messages.pot -d locales -l en
   
   # Update Arabic translations
   pybabel update -i locales/messages.pot -d locales -l ar
   ```

3. **Add new language**:
   ```bash
   # Create new language directory
   pybabel init -i locales/messages.pot -d locales -l fr
   ```

### Translation Workflow

1. **Edit `.po` files** in your preferred text editor
2. **Compile translations**:
   ```bash
   pybabel compile -d locales
   ```
3. **Restart the application** to load new translations

### Example Translation File

```po
# locales/en/LC_MESSAGES/messages.po
msgid "user_registered_successfully"
msgstr "User registered successfully"

msgid "invalid_credentials"
msgstr "Invalid username or password"

msgid "password_reset_email_sent"
msgstr "If an account with that email exists, a password reset link has been sent."

# locales/ar/LC_MESSAGES/messages.po
msgid "user_registered_successfully"
msgstr "تم تسجيل المستخدم بنجاح"

msgid "invalid_credentials"
msgstr "اسم المستخدم أو كلمة المرور غير صحيحة"

msgid "password_reset_email_sent"
msgstr "إذا كان هناك حساب بهذا البريد الإلكتروني، فقد تم إرسال رابط إعادة تعيين كلمة المرور."
```

## Configuration

### Environment Variables

```bash
# Default language
DEFAULT_LANGUAGE=en

# Supported languages (comma-separated)
SUPPORTED_LANGUAGES=en,ar,es,fa

# Locale directory
LOCALE_DIR=locales
```

### Application Settings

```python
# src/core/config/settings.py
class Settings(BaseSettings):
    DEFAULT_LANGUAGE: str = "en"
    SUPPORTED_LANGUAGES: List[str] = ["en", "ar", "es", "fa"]
    LOCALE_DIR: str = "locales"
```

## Best Practices

### Message Keys

- Use descriptive, hierarchical keys: `auth.login.success`, `auth.login.invalid_credentials`
- Keep keys consistent across the application
- Use lowercase with underscores for readability

### Translation Guidelines

- **Context**: Provide context for translators in comments
- **Variables**: Use placeholders for dynamic content: `"Welcome, {username}!"`
- **Pluralization**: Handle plural forms correctly
- **Cultural Sensitivity**: Consider cultural differences in messaging

### Performance

- Compiled `.mo` files are loaded at startup
- Language detection is cached per request
- Minimal overhead for translation lookups

## Adding a New Language

### Step 1: Initialize Language

```bash
# Create new language directory and files
pybabel init -i locales/messages.pot -d locales -l ja
```

### Step 2: Translate Messages

Edit `locales/ja/LC_MESSAGES/messages.po`:
```po
msgid "user_registered_successfully"
msgstr "ユーザーが正常に登録されました"

msgid "invalid_credentials"
msgstr "ユーザー名またはパスワードが無効です"
```

### Step 3: Compile and Test

```bash
# Compile translations
pybabel compile -d locales

# Test the new language
curl -H "Accept-Language: ja" http://localhost:8000/api/v1/auth/login
```

### Step 4: Update Configuration

```python
# Add to supported languages
SUPPORTED_LANGUAGES = ["en", "ar", "es", "fa", "ja"]
```

## Testing

### Unit Tests

```python
def test_translation_fallback():
    # Test fallback to default language
    message = get_translated_message("unknown_key", "invalid_lang")
    assert message == "unknown_key"  # Falls back to key

def test_language_detection():
    # Test language detection from headers
    request = Mock()
    request.headers = {"accept-language": "ar,en;q=0.9"}
    language = get_request_language(request)
    assert language == "ar"
```

### Integration Tests

```python
async def test_localized_error_messages():
    # Test that error messages are properly localized
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": "invalid", "password": "invalid"},
        headers={"Accept-Language": "ar"}
    )
    assert response.status_code == 401
    # Verify Arabic error message
```

## Troubleshooting

### Common Issues

1. **Translations not loading**: Ensure `.mo` files are compiled and up-to-date
2. **Wrong language detected**: Check `Accept-Language` header format
3. **Missing translations**: Add missing keys to `.po` files and recompile

### Debug Commands

```bash
# Check translation status
pybabel list -d locales

# Validate .po files
msgfmt --check locales/en/LC_MESSAGES/messages.po

# Extract new messages
pybabel extract -F babel.cfg -k _l -o locales/messages.pot .
```

## Next Steps

- Review the [Configuration Guide](getting-started/configuration.md) for i18n settings
- Check the [API Documentation](development/api-docs.md) for endpoint localization
- Explore the [Testing Guide](development/testing.md) for i18n testing strategies 