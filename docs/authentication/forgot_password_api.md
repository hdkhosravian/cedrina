# Forgot Password API Documentation

## Overview

This document provides comprehensive API documentation for the forgot password and reset password endpoints, including request/response formats, error handling, and integration examples.

## 🔗 API Endpoints

### Base URL
```
https://api.yourdomain.com/api/v1/auth
```

## 1. Request Password Reset

### Endpoint
```http
POST /forgot-password
```

### Description
Initiates a password reset process by sending a secure reset link to the user's email address.

### Request Format

#### Headers
```http
Content-Type: application/json
Accept: application/json
Accept-Language: en|es|fa|ar (optional)
```

#### Request Body
```json
{
    "email": "user@example.com",
    "language": "en"
}
```

#### Parameters
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `email` | string (email) | Yes | Valid email address of the user |
| `language` | string | No | Language code for localization (en, es, fa, ar). Default: "en" |

### Response Format

#### Success Response (200 OK)
```json
{
    "message": "Password reset email has been sent to your email address",
    "status": "success"
}
```

#### Error Responses

**Rate Limited (429 Too Many Requests)**
```json
{
    "detail": "Rate limit exceeded. Please wait before making another request",
    "code": "RATE_LIMIT_EXCEEDED"
}
```

**Email Service Error (500 Internal Server Error)**
```json
{
    "detail": "Failed to send password reset email",
    "code": "EMAIL_SERVICE_ERROR"
}
```

**Validation Error (422 Unprocessable Entity)**
```json
{
    "detail": [
        {
            "loc": ["body", "email"],
            "msg": "field required",
            "type": "value_error.missing"
        }
    ]
}
```

### Security Notes
- Returns consistent success message regardless of email existence (prevents email enumeration)
- Rate limited to prevent abuse (5-minute window between requests per user)
- Email validation performed server-side

### Example Requests

#### cURL
```bash
curl -X POST "https://api.yourdomain.com/api/v1/auth/forgot-password" \
     -H "Content-Type: application/json" \
     -H "Accept-Language: en" \
     -d '{
       "email": "user@example.com",
       "language": "en"
     }'
```

#### JavaScript (Fetch API)
```javascript
const response = await fetch('/api/v1/auth/forgot-password', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Accept-Language': 'en'
    },
    body: JSON.stringify({
        email: 'user@example.com',
        language: 'en'
    })
});

const result = await response.json();
```

#### Python (requests)
```python
import requests

response = requests.post(
    'https://api.yourdomain.com/api/v1/auth/forgot-password',
    headers={
        'Content-Type': 'application/json',
        'Accept-Language': 'en'
    },
    json={
        'email': 'user@example.com',
        'language': 'en'
    }
)

result = response.json()
```

## 2. Reset Password

### Endpoint
```http
POST /reset-password
```

### Description
Resets a user's password using a valid reset token received via email.

### Request Format

#### Headers
```http
Content-Type: application/json
Accept: application/json
Accept-Language: en|es|fa|ar (optional)
```

#### Request Body
```json
{
    "token": "a1b2c3d4e5f6789...",
    "new_password": "NewSecurePassword123!",
    "language": "en"
}
```

#### Parameters
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | 64-character reset token from email |
| `new_password` | string | Yes | New password meeting strength requirements |
| `language` | string | No | Language code for localization. Default: "en" |

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter  
- At least one number
- At least one special character
- Maximum 128 characters

### Response Format

#### Success Response (200 OK)
```json
{
    "message": "Password has been reset successfully",
    "status": "success"
}
```

#### Error Responses

**Invalid Token (400 Bad Request)**
```json
{
    "detail": "Invalid or expired password reset token",
    "code": "INVALID_TOKEN"
}
```

**Weak Password (400 Bad Request)**
```json
{
    "detail": "Password does not meet security requirements",
    "code": "WEAK_PASSWORD"
}
```

**Token Expired (400 Bad Request)**
```json
{
    "detail": "Password reset token has expired",
    "code": "TOKEN_EXPIRED"
}
```

**User Not Found (400 Bad Request)**
```json
{
    "detail": "User associated with token not found",
    "code": "USER_NOT_FOUND"
}
```

### Security Notes
- Tokens expire after 5 minutes
- Tokens are single-use only (invalidated after successful reset)
- Constant-time validation prevents timing attacks
- Token format validation prevents injection attacks

### Example Requests

#### cURL
```bash
curl -X POST "https://api.yourdomain.com/api/v1/auth/reset-password" \
     -H "Content-Type: application/json" \
     -H "Accept-Language: en" \
     -d '{
       "token": "a1b2c3d4e5f6789...",
       "new_password": "NewSecurePassword123!",
       "language": "en"
     }'
```

#### JavaScript (Fetch API)
```javascript
const response = await fetch('/api/v1/auth/reset-password', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Accept-Language': 'en'
    },
    body: JSON.stringify({
        token: 'a1b2c3d4e5f6789...',
        new_password: 'NewSecurePassword123!',
        language: 'en'
    })
});

const result = await response.json();
```

#### Python (requests)
```python
import requests

response = requests.post(
    'https://api.yourdomain.com/api/v1/auth/reset-password',
    headers={
        'Content-Type': 'application/json',
        'Accept-Language': 'en'
    },
    json={
        'token': 'a1b2c3d4e5f6789...',
        'new_password': 'NewSecurePassword123!',
        'language': 'en'
    }
)

result = response.json()
```

## 🔐 Security Considerations

### Rate Limiting
- **Forgot Password**: Maximum 1 request per 5 minutes per user
- **Reset Password**: No specific rate limit (tokens expire quickly)

### Token Security
- **Entropy**: 256-bit cryptographically secure tokens
- **Expiration**: 5-minute maximum lifetime
- **Single Use**: Tokens invalidated immediately after use
- **Format**: Exactly 64 hexadecimal characters
- **Validation**: Constant-time comparison to prevent timing attacks

### Email Security
- **Enumeration Protection**: Consistent responses regardless of email existence
- **Secure URLs**: HTTPS-only reset links
- **Template Security**: HTML escaping and safe rendering
- **Multi-language**: Localized templates with fallbacks

## 🌐 Internationalization

### Supported Languages
| Code | Language | RTL Support |
|------|----------|-------------|
| `en` | English | No |
| `es` | Spanish | No |
| `fa` | Persian | Yes |
| `ar` | Arabic | Yes |

### Language Selection
1. **Request Parameter**: Use `language` field in request body
2. **Accept-Language Header**: Fallback to header value
3. **Default**: English (`en`) if no preference specified

### Error Messages
All error messages are localized based on the selected language:

#### English (en)
```json
{
    "password_reset_email_sent": "Password reset email has been sent to your email address",
    "password_reset_token_invalid": "Invalid or expired password reset token",
    "password_reset_success": "Password has been reset successfully",
    "password_too_weak": "Password does not meet security requirements"
}
```

#### Spanish (es)
```json
{
    "password_reset_email_sent": "Se ha enviado un correo de restablecimiento de contraseña a su dirección de correo",
    "password_reset_token_invalid": "Token de restablecimiento de contraseña inválido o expirado",
    "password_reset_success": "La contraseña ha sido restablecida exitosamente",
    "password_too_weak": "La contraseña no cumple con los requisitos de seguridad"
}
```

## 🧪 Testing

### Test Endpoints

For development and testing, you can use these endpoints:

#### Health Check
```http
GET /health
```

#### Test Email (Development Only)
```http
POST /test-email
```

### Integration Testing

#### Test Flow Example
```python
import requests
import time

# Step 1: Request password reset
response = requests.post('/api/v1/auth/forgot-password', json={
    'email': 'test@example.com',
    'language': 'en'
})
assert response.status_code == 200

# Step 2: Extract token from email (in tests, this would be mocked)
token = extract_token_from_email()  # Implementation depends on test setup

# Step 3: Reset password
response = requests.post('/api/v1/auth/reset-password', json={
    'token': token,
    'new_password': 'NewSecurePassword123!',
    'language': 'en'
})
assert response.status_code == 200
```

### Error Handling Tests

```python
# Test invalid email format
response = requests.post('/api/v1/auth/forgot-password', json={
    'email': 'invalid-email',
    'language': 'en'
})
assert response.status_code == 422

# Test expired token
response = requests.post('/api/v1/auth/reset-password', json={
    'token': 'expired_token_here',
    'new_password': 'NewPassword123!',
    'language': 'en'
})
assert response.status_code == 400

# Test weak password
response = requests.post('/api/v1/auth/reset-password', json={
    'token': 'valid_token_here',
    'new_password': '123',
    'language': 'en'
})
assert response.status_code == 400
```

## 📝 OpenAPI Schema

### Forgot Password Request Schema
```yaml
ForgotPasswordRequest:
  type: object
  required:
    - email
  properties:
    email:
      type: string
      format: email
      description: User's email address
      example: "user@example.com"
    language:
      type: string
      enum: [en, es, fa, ar]
      default: en
      description: Language code for localization
      example: "en"
```

### Reset Password Request Schema
```yaml
ResetPasswordRequest:
  type: object
  required:
    - token
    - new_password
  properties:
    token:
      type: string
      pattern: "^[a-f0-9]{64}$"
      description: 64-character hexadecimal reset token
      example: "a1b2c3d4e5f6789abcdef1234567890abcdef1234567890abcdef1234567890"
    new_password:
      type: string
      minLength: 8
      maxLength: 128
      description: New password meeting security requirements
      example: "NewSecurePassword123!"
    language:
      type: string
      enum: [en, es, fa, ar]
      default: en
      description: Language code for localization
      example: "en"
```

### Response Schemas
```yaml
SuccessResponse:
  type: object
  properties:
    message:
      type: string
      description: Localized success message
    status:
      type: string
      enum: [success]
      description: Operation status

ErrorResponse:
  type: object
  properties:
    detail:
      type: string
      description: Error message
    code:
      type: string
      description: Error code for programmatic handling
```

## 🚀 Integration Examples

### Frontend Integration (React)

```typescript
interface ForgotPasswordRequest {
    email: string;
    language?: string;
}

interface ResetPasswordRequest {
    token: string;
    new_password: string;
    language?: string;
}

class AuthAPI {
    private baseURL = '/api/v1/auth';

    async requestPasswordReset(data: ForgotPasswordRequest): Promise<void> {
        const response = await fetch(`${this.baseURL}/forgot-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept-Language': data.language || 'en'
            },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Password reset request failed');
        }
    }

    async resetPassword(data: ResetPasswordRequest): Promise<void> {
        const response = await fetch(`${this.baseURL}/reset-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept-Language': data.language || 'en'
            },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Password reset failed');
        }
    }
}
```

### Mobile Integration (React Native)

```typescript
import AsyncStorage from '@react-native-async-storage/async-storage';

class MobileAuthAPI {
    private async getLanguage(): Promise<string> {
        return await AsyncStorage.getItem('language') || 'en';
    }

    async requestPasswordReset(email: string): Promise<void> {
        const language = await this.getLanguage();
        
        const response = await fetch('/api/v1/auth/forgot-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept-Language': language
            },
            body: JSON.stringify({ email, language })
        });

        if (!response.ok) {
            throw new Error('Password reset request failed');
        }
    }

    async resetPassword(token: string, newPassword: string): Promise<void> {
        const language = await this.getLanguage();
        
        const response = await fetch('/api/v1/auth/reset-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept-Language': language
            },
            body: JSON.stringify({
                token,
                new_password: newPassword,
                language
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Password reset failed');
        }
    }
}
```

## 📊 Monitoring & Analytics

### Key Metrics to Track

1. **Usage Metrics**
   - Password reset requests per day/hour
   - Reset completion rate
   - Language preference distribution
   - Email delivery success rate

2. **Security Metrics**
   - Failed token validation attempts
   - Rate limiting activations
   - Token expiration rates
   - Suspicious activity patterns

3. **Performance Metrics**
   - API response times
   - Email delivery times
   - Database query performance
   - Error rates by endpoint

### Sample Monitoring Code

```python
import time
from typing import Dict, Any

class APIMonitoring:
    def __init__(self, metrics_client):
        self.metrics = metrics_client
    
    def track_forgot_password_request(self, email: str, language: str, success: bool):
        self.metrics.increment('forgot_password.requests', tags={
            'language': language,
            'success': success
        })
    
    def track_reset_password_attempt(self, success: bool, error_type: str = None):
        self.metrics.increment('reset_password.attempts', tags={
            'success': success,
            'error_type': error_type or 'none'
        })
    
    def track_api_latency(self, endpoint: str, duration: float):
        self.metrics.histogram('api.latency', duration, tags={
            'endpoint': endpoint
        })
```

---

*This API documentation provides complete integration guidance for the forgot password and reset password functionality. For additional implementation details, refer to the main system documentation.* 