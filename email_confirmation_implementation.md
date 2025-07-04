# Email Confirmation Feature Implementation

## Overview

This document outlines the implementation of the email confirmation feature for the Cedrina authentication system. The feature allows administrators to require email verification before users can log in to the system.

## Feature Flag

- **Setting**: `EMAIL_CONFIRMATION_ENABLED`
- **Default**: `false`
- **Type**: Boolean
- **Environment Variable**: `EMAIL_CONFIRMATION_ENABLED`

## Database Changes

### New Fields Added to User Entity

The following fields were added to the `users` table:

```sql
-- Email confirmation status
email_confirmed BOOLEAN NOT NULL DEFAULT FALSE;

-- Email confirmation token (64 characters max)
email_confirmation_token VARCHAR(64) NULL;

-- Timestamp when email was confirmed
email_confirmed_at TIMESTAMP NULL;
```

### Migration

- **File**: `alembic/versions/ec964d9b5e69_add_email_confirmation_fields.py`
- **Description**: Adds email confirmation fields to users table

## Architecture

The implementation follows Domain-Driven Design principles and clean architecture:

### Domain Layer

1. **Email Confirmation Service Interface** (`IEmailConfirmationService`)
   - Defines contract for email confirmation operations
   - Located: `src/domain/interfaces/email_confirmation.py`

2. **Email Confirmation Service Implementation** (`EmailConfirmationService`)
   - Handles business logic for email confirmation
   - Token generation and validation
   - Email sending coordination
   - Located: `src/domain/services/email_confirmation/email_confirmation_service.py`

### Infrastructure Layer

1. **Email Service** (`EmailService`)
   - Handles actual email sending
   - Template rendering
   - SMTP configuration
   - Located: `src/infrastructure/services/email/email_service.py`

2. **Repository Updates** (`UserRepository`)
   - Added `get_by_email_confirmation_token()` method
   - Added `update()` method
   - Located: `src/infrastructure/repositories/user_repository.py`

### API Layer

1. **Email Confirmation Routes**
   - `POST /auth/confirm-email/confirm` - Confirm email with token
   - `POST /auth/confirm-email/resend` - Resend confirmation email
   - Located: `src/adapters/api/v1/auth/routes/confirm_email.py`

## Workflow

### Registration Flow

#### When Email Confirmation is DISABLED (default):
1. User registers with username, email, and password
2. User is created with `is_active = true`
3. User can log in immediately
4. No confirmation email is sent

#### When Email Confirmation is ENABLED:
1. User registers with username, email, and password
2. User is created with `is_active = false` and `email_confirmed = false`
3. Confirmation token is generated and stored
4. Confirmation email is sent to user
5. User cannot log in until email is confirmed

### Email Confirmation Flow

1. User clicks confirmation link in email
2. System validates token
3. If valid:
   - Set `email_confirmed = true`
   - Set `email_confirmed_at = current_timestamp`
   - Clear `email_confirmation_token`
   - Set `is_active = true` (if email confirmation is enabled)
4. User can now log in

### Login Flow

#### When Email Confirmation is DISABLED:
- Standard authentication checks
- Users can log in if account is active

#### When Email Confirmation is ENABLED:
- Standard authentication checks
- Additional check: if `is_active = false`, check if it's due to unconfirmed email
- If email not confirmed, return 401 with specific error message
- If email confirmed, proceed with login

### Resend Confirmation Email

1. User provides email address
2. System looks up user by email
3. If user exists and email not confirmed, sends new confirmation email
4. If user doesn't exist or email already confirmed, returns success (prevents enumeration)

## Security Features

1. **Token Security**
   - Uses `secrets.token_urlsafe(32)` for cryptographically secure tokens
   - 32 bytes = 256 bits of entropy
   - Tokens are URL-safe and unique

2. **Email Enumeration Prevention**
   - Resend endpoint always returns success
   - Doesn't reveal whether email exists in system

3. **No Token Expiration**
   - Confirmation tokens don't expire (as per requirements)
   - Tokens are invalidated once used

4. **Secure Logging**
   - All sensitive data is masked in logs
   - Comprehensive audit trails

## Configuration

### Environment Variables

```bash
# Feature flag
EMAIL_CONFIRMATION_ENABLED=false

# Email configuration (existing)
EMAIL_SMTP_HOST=smtp.example.com
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USERNAME=your_smtp_user
EMAIL_SMTP_PASSWORD=your_smtp_password
EMAIL_FROM_EMAIL=noreply@example.com
EMAIL_FROM_NAME=Cedrina
EMAIL_TEST_MODE=false

# Frontend URL for confirmation links
PASSWORD_RESET_URL_BASE=http://localhost:3000
```

### Frontend Integration

Confirmation emails contain links that redirect to the frontend:
```
{FRONTEND_URL}/confirm-email?token={confirmation_token}
```

The frontend should:
1. Extract token from URL
2. Call `POST /auth/confirm-email/confirm` with token
3. Handle success/error responses
4. Redirect user appropriately

## API Endpoints

### Confirm Email
```http
POST /auth/confirm-email/confirm
Content-Type: application/json

{
  "token": "confirmation_token_here"
}
```

**Success Response (200):**
```json
{
  "message": "Email confirmed successfully",
  "user": {
    "id": 1,
    "username": "testuser",
    "email": "test@example.com",
    "email_confirmed": true,
    "is_active": true
  }
}
```

**Error Response (400):**
```json
{
  "detail": "Invalid or expired email confirmation token"
}
```

### Resend Confirmation Email
```http
POST /auth/confirm-email/resend
Content-Type: application/json

{
  "email": "user@example.com"
}
```

**Success Response (200):**
```json
{
  "message": "If the email address is registered, you will receive a confirmation email shortly"
}
```

## Testing

### Unit Tests
- **Location**: `tests/unit/domain/services/test_email_confirmation_service.py`
- **Coverage**: Email confirmation service methods
- **Scenarios**: Success, failure, edge cases

### Feature Tests
- **Location**: `tests/feature/test_email_confirmation_flow.py`
- **Coverage**: End-to-end workflows
- **Scenarios**: Registration, login, confirmation flows

### Test Scenarios Covered

1. **Registration with email confirmation enabled/disabled**
2. **Email confirmation with valid/invalid tokens**
3. **Resend confirmation for existing/non-existing users**
4. **Login blocking when email not confirmed**
5. **Login allowing when email confirmed**
6. **Token generation uniqueness**
7. **Service dependency injection**

## I18N Support

All user-facing messages are internationalized:

```
# Email confirmation messages
email_confirmation_subject = "Confirm Your Email Address - Cedrina"
email_confirmation_send_failed = "Failed to send email confirmation"
email_confirmation_failed = "Email confirmation failed"
email_confirmation_resend_failed = "Failed to resend email confirmation"
invalid_email_confirmation_token = "Invalid or expired email confirmation token"
email_confirmation_required = "Please confirm your email address before logging in"
welcome_email_subject = "Welcome to Cedrina"
email_confirmed_successfully = "Email address confirmed successfully"
email_confirmation_already_confirmed = "Email address is already confirmed"
```

## Deployment Considerations

1. **Database Migration**: Run the Alembic migration to add new fields
2. **Environment Variables**: Set `EMAIL_CONFIRMATION_ENABLED` as needed
3. **Email Configuration**: Ensure SMTP settings are properly configured
4. **Frontend Updates**: Update frontend to handle confirmation flow
5. **Monitoring**: Monitor email sending success rates and confirmation rates

## Real-World Usage Recommendations

1. **Gradual Rollout**: Start with `EMAIL_CONFIRMATION_ENABLED=false`, enable gradually
2. **Email Templates**: Customize email templates for your brand
3. **Monitoring**: Set up alerts for failed email deliveries
4. **User Experience**: Provide clear instructions in confirmation emails
5. **Support Process**: Have process for users who don't receive emails
6. **Cleanup**: Consider periodic cleanup of unconfirmed old accounts
7. **Rate Limiting**: Monitor and limit confirmation email sending rates
8. **Analytics**: Track confirmation rates to optimize the flow

## Future Enhancements

1. **Token Expiration**: Add configurable token expiration
2. **Email Templates**: Rich HTML email templates
3. **Bulk Operations**: Admin endpoints for bulk email confirmation management
4. **Analytics Dashboard**: Confirmation rate analytics
5. **Alternative Verification**: SMS or other verification methods
6. **Reminder Emails**: Automatic reminder emails for unconfirmed accounts

## Dependencies

### New Dependencies Added
- None (used existing dependencies)

### Services Used
- `secrets` module for token generation
- `fastapi-mail` for email sending (existing)
- `structlog` for logging (existing)
- `babel` for I18N (existing)

## File Structure

```
src/
├── domain/
│   ├── interfaces/
│   │   └── email_confirmation.py          # Interface definition
│   └── services/
│       └── email_confirmation/
│           ├── __init__.py
│           └── email_confirmation_service.py  # Service implementation
├── infrastructure/
│   ├── services/
│   │   └── email/
│   │       ├── __init__.py
│   │       └── email_service.py           # Email sending service
│   └── dependency_injection/
│       └── auth_dependencies.py           # DI configuration
├── adapters/
│   └── api/
│       └── v1/
│           └── auth/
│               └── routes/
│                   └── confirm_email.py   # API endpoints
└── core/
    └── config/
        └── settings.py                    # Feature flag

tests/
├── unit/
│   └── domain/
│       └── services/
│           └── test_email_confirmation_service.py  # Unit tests
└── feature/
    └── test_email_confirmation_flow.py    # Feature tests

alembic/
└── versions/
    └── ec964d9b5e69_add_email_confirmation_fields.py  # Migration

locales/
└── en/
    └── LC_MESSAGES/
        └── messages.po                    # I18N messages
```

This implementation provides a robust, secure, and flexible email confirmation system that integrates seamlessly with the existing Cedrina authentication architecture.