# Forgot Password & Reset Password System

## Overview

The Cedrina application includes a comprehensive, enterprise-grade forgot password and reset password system built with Domain-Driven Design (DDD) principles, Test-Driven Development (TDD), and advanced security practices. This system provides secure password recovery functionality with robust protection against common attack vectors.

## 🔒 Security Features

### Advanced Security Measures
- **5-minute token expiration** - Minimal attack window
- **One-time use tokens** - Immediate invalidation after use
- **Timing attack protection** - Constant-time token validation
- **Rate limiting** - Protection against brute force attacks
- **Email enumeration protection** - Consistent responses
- **Token format validation** - Prevents injection attacks
- **Cryptographically secure tokens** - 256-bit entropy using `secrets.token_hex(32)`
- **Comprehensive audit logging** - Security monitoring and incident response
- **Multi-language support** - Localized security error messages

### Security Validations
- Password strength validation
- Token expiration enforcement  
- User activation status checks
- Cross-user token isolation
- Database failure recovery
- Email delivery confirmation

## 🏗️ Architecture

The system follows Domain-Driven Design with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Application Layer                          │
│  ┌─────────────────┐    ┌─────────────────┐                   │
│  │   API Routes    │    │   Controllers   │                   │
│  └─────────────────┘    └─────────────────┘                   │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                     Domain Layer                               │
│  ┌─────────────────┐    ┌─────────────────┐                   │
│  │ ForgotPassword  │    │PasswordReset    │                   │
│  │    Service      │    │ TokenService    │                   │
│  └─────────────────┘    └─────────────────┘                   │
│  ┌─────────────────┐    ┌─────────────────┐                   │
│  │PasswordReset    │    │  User Entity    │                   │
│  │ EmailService    │    │                 │                   │
│  └─────────────────┘    └─────────────────┘                   │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                  Infrastructure Layer                          │
│  ┌─────────────────┐    ┌─────────────────┐                   │
│  │ UserRepository  │    │  Email Service  │                   │
│  └─────────────────┘    └─────────────────┘                   │
│  ┌─────────────────┐    ┌─────────────────┐                   │
│  │   Database      │    │ Email Templates │                   │
│  └─────────────────┘    └─────────────────┘                   │
└─────────────────────────────────────────────────────────────────┘
```

## 📂 Core Components

### 1. ForgotPasswordService
**Location**: `src/domain/services/forgot_password/forgot_password_service.py`

Main orchestration service that handles the complete workflow:
- Email validation and user lookup
- Rate limiting enforcement
- Token generation coordination
- Email delivery orchestration
- Error handling and logging

**Key Methods**:
- `request_password_reset(email, language)` - Initiates password reset
- `reset_password(token, new_password, language)` - Completes password reset
- `cleanup_expired_tokens()` - Maintenance operation

### 2. PasswordResetTokenService
**Location**: `src/domain/services/auth/password_reset_token_service.py`

Handles secure token operations:
- Cryptographically secure token generation
- Constant-time token validation
- Token expiration management
- One-time use enforcement

**Key Methods**:
- `generate_token(user, expire_minutes)` - Creates secure token
- `is_token_valid(user, token)` - Validates token with timing protection
- `invalidate_token(user, reason)` - Clears token for security
- `is_token_expired(user)` - Checks expiration status

### 3. PasswordResetEmailService
**Location**: `src/domain/services/forgot_password/password_reset_email_service.py`

Dedicated service for password reset emails:
- Template rendering with security
- Multi-language support with fallbacks
- URL building with secure tokens
- Email context preparation

**Key Methods**:
- `send_password_reset_email(user, token, language)` - Sends reset email

### 4. User Entity Extensions
**Location**: `src/domain/entities/user.py`

User entity includes password reset fields:
- `password_reset_token` - 64-character hex token
- `password_reset_token_expires_at` - UTC expiration timestamp

### 5. Email Templates
**Location**: `src/templates/email/`

Professional email templates in 4 languages:
- English: `password_reset_en.html`, `password_reset_en.txt`
- Spanish: `password_reset_es.html`, `password_reset_es.txt`
- Persian: `password_reset_fa.html`, `password_reset_fa.txt` (RTL support)
- Arabic: `password_reset_ar.html`, `password_reset_ar.txt` (RTL support)

## 🔄 Workflow

### Forgot Password Flow

1. **User Request** - User provides email address
2. **Validation** - Email format and user lookup validation
3. **Rate Limiting** - Check for recent requests (5-minute window)
4. **Token Generation** - Generate cryptographically secure 64-char token
5. **Email Delivery** - Send multilingual email with reset link
6. **Database Update** - Store token with 5-minute expiration
7. **Response** - Return success message (consistent for security)

### Reset Password Flow

1. **Token Validation** - Format, existence, and expiration checks
2. **User Lookup** - Find user by token using timing-safe operations
3. **Password Validation** - Strength requirements enforcement
4. **Password Update** - Hash and store new password
5. **Token Invalidation** - Immediate one-time use enforcement
6. **Database Update** - Save changes atomically
7. **Response** - Return success message

## 🌐 Multi-language Support

The system supports 4 languages with proper I18N:

### Supported Languages
- **English (en)** - Default language
- **Spanish (es)** - Full localization
- **Persian (fa)** - RTL support included
- **Arabic (ar)** - RTL support included

### Localized Messages
- `password_reset_email_subject` - Email subject line
- `password_reset_email_sent` - Confirmation message
- `password_reset_token_invalid` - Invalid token error
- `password_reset_success` - Success confirmation
- `password_too_weak` - Weak password error
- `password_reset_failed` - General failure message

## ⚙️ Configuration

### Email Settings
**Location**: `src/core/config/email.py`

```python
class EmailSettings(BaseSettings):
    # SMTP Configuration
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_TLS: bool = True
    
    # Email Settings
    FROM_EMAIL: str = "noreply@example.com"
    FROM_NAME: str = "Cedrina"
    
    # Password Reset Configuration
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 5
    PASSWORD_RESET_URL_BASE: str = "https://app.example.com/reset-password"
    
    # Template Settings
    EMAIL_TEMPLATES_DIR: str = "src/templates/email"
    
    # Security Settings
    EMAIL_TEST_MODE: bool = False
```

### Environment Variables

```bash
# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_TLS=true

# Application URLs
PASSWORD_RESET_URL_BASE=https://yourdomain.com/reset-password

# Security Settings
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES=5
EMAIL_TEST_MODE=false
```

## 🧪 Testing

The system includes comprehensive test coverage:

### Test Categories
- **Unit Tests** (62 tests) - Individual component testing
- **Feature Tests** (13 tests) - Real-world security scenarios
- **Integration Tests** - End-to-end workflow testing

### Key Test Scenarios
- **Security Attack Simulations**
  - Rapid-fire attack scenarios
  - Timing attack resistance
  - Token enumeration prevention
  - Concurrent attack handling

- **Token Security**
  - 5-minute expiration enforcement
  - One-time use validation
  - Format validation
  - Cross-user isolation

- **Error Handling**
  - Database failure recovery
  - Email delivery failures
  - Multi-language error messages
  - Weak password attempts

### Running Tests

```bash
# Run all forgot password tests
make test-forgot-password

# Run specific test categories
pytest tests/unit/services/test_forgot_password_service.py -v
pytest tests/feature/auth/test_forgot_password_security_scenarios.py -v
pytest tests/unit/entities/test_user_password_reset.py -v
```

## 🔐 Security Best Practices

### Implementation Guidelines

1. **Token Security**
   - Always use 5-minute expiration maximum
   - Implement one-time use strictly
   - Use constant-time comparison
   - Log security events comprehensively

2. **Rate Limiting**
   - Enforce minimum 5-minute intervals
   - Track per-user request patterns
   - Implement exponential backoff for abuse

3. **Email Security**
   - Validate email format strictly
   - Prevent email enumeration attacks
   - Use secure URL schemes only
   - Include security warnings in emails

4. **Error Handling**
   - Never leak system internals
   - Provide consistent response times
   - Log security violations
   - Fail securely in all scenarios

### Security Monitoring

Key metrics to monitor:
- Token generation frequency per user
- Failed token validation attempts
- Email delivery failure rates
- Password reset completion rates
- Concurrent request patterns

## 🚀 Usage Examples

### Service Integration

```python
from src.domain.services.forgot_password.forgot_password_service import ForgotPasswordService
from src.domain.services.forgot_password.password_reset_email_service import PasswordResetEmailService
from src.infrastructure.repositories.user_repository import UserRepository

# Initialize dependencies
user_repository = UserRepository()
email_service = PasswordResetEmailService(email_service, settings)
forgot_service = ForgotPasswordService(user_repository, email_service)

# Request password reset
result = await forgot_service.request_password_reset(
    email="user@example.com",
    language="en"
)

# Reset password with token
result = await forgot_service.reset_password(
    token="a1b2c3d4...",  # 64-character token
    new_password="NewSecurePassword123!",
    language="en"
)
```

### API Integration

```python
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr

class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    language: str = "en"

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
    language: str = "en"

router = APIRouter()

@router.post("/forgot-password")
async def request_password_reset(
    request: ForgotPasswordRequest,
    service: ForgotPasswordService = Depends(get_forgot_password_service)
):
    try:
        result = await service.request_password_reset(
            email=request.email,
            language=request.language
        )
        return result
    except RateLimitExceededError:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    except EmailServiceError:
        raise HTTPException(status_code=500, detail="Email delivery failed")

@router.post("/reset-password")
async def reset_password(
    request: ResetPasswordRequest,
    service: ForgotPasswordService = Depends(get_forgot_password_service)
):
    try:
        result = await service.reset_password(
            token=request.token,
            new_password=request.new_password,
            language=request.language
        )
        return result
    except PasswordResetError as e:
        raise HTTPException(status_code=400, detail=str(e))
```

## 🛠️ Maintenance

### Regular Maintenance Tasks

1. **Token Cleanup** - Run periodic cleanup of expired tokens:
   ```python
   # Schedule this as a cron job or background task
   cleaned_count = await forgot_service.cleanup_expired_tokens()
   logger.info(f"Cleaned {cleaned_count} expired tokens")
   ```

2. **Security Monitoring** - Monitor logs for:
   - Unusual token generation patterns
   - Failed validation attempts
   - Rate limiting violations
   - Email delivery failures

3. **Performance Optimization**
   - Monitor token validation response times
   - Optimize database queries for token lookups
   - Cache frequently accessed configuration

## 📊 Metrics & Monitoring

### Key Performance Indicators

- **Security Metrics**
  - Token validation success rate
  - Average token usage time
  - Failed authentication attempts
  - Rate limiting trigger frequency

- **Operational Metrics**
  - Email delivery success rate
  - Password reset completion rate
  - System response times
  - Error rates by category

### Alerting Recommendations

Set up alerts for:
- High failure rates (>5%)
- Unusual token generation spikes
- Email delivery failures
- Security violation patterns
- System performance degradation

## 🔄 Future Enhancements

### Planned Improvements

1. **Enhanced Security**
   - CAPTCHA integration for additional protection
   - Device fingerprinting for risk assessment
   - Geographic anomaly detection

2. **User Experience**
   - Progressive web app support
   - Mobile-optimized templates
   - Real-time validation feedback

3. **Enterprise Features**
   - SSO integration support
   - Advanced audit logging
   - Custom security policies

---

*This documentation covers the complete forgot password and reset password system implementation. For technical support or questions, please refer to the test suites and source code comments for additional details.* 