# Change Password API Documentation

## Overview

The Change Password API is a secure endpoint that allows authenticated users to change their passwords with comprehensive validation and security measures. This feature implements enterprise-grade security practices including old password verification, password policy enforcement, and audit logging.

**Endpoint**: `PUT /api/v1/auth/change-password`  
**Authentication**: Required (JWT Bearer Token)  
**Content-Type**: `application/json`

## Security Features

### Core Security Principles

1. **Authentication Required**: Only authenticated users can change their own password
2. **Old Password Validation**: Current password must be verified before allowing change
3. **Password Policy Enforcement**: New password must meet global security requirements
4. **Password Reuse Prevention**: New password must differ from the old password
5. **Audit Logging**: All password changes are logged for security monitoring
6. **Input Validation**: Comprehensive validation of all input parameters
7. **SQL Injection Protection**: Uses parameterized queries throughout

### Password Policy Requirements

The new password must meet the following criteria:
- **Minimum Length**: 8 characters
- **Uppercase Letters**: At least one uppercase letter (A-Z)
- **Lowercase Letters**: At least one lowercase letter (a-z)
- **Digits**: At least one digit (0-9)
- **Special Characters**: At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)

## API Specification

### Request

```http
PUT /api/v1/auth/change-password
Authorization: Bearer <jwt_access_token>
Content-Type: application/json

{
  "old_password": "CurrentPassword123!",
  "new_password": "NewSecurePassword456!"
}
```

### Request Schema

```json
{
  "type": "object",
  "properties": {
    "old_password": {
      "type": "string",
      "description": "Current password for verification",
      "minLength": 1
    },
    "new_password": {
      "type": "string", 
      "description": "New password to set",
      "minLength": 1
    }
  },
  "required": ["old_password", "new_password"]
}
```

### Response

#### Success Response (200 OK)

```json
{
  "message": "Password changed successfully"
}
```

#### Error Responses

**400 Bad Request** - Invalid old password or password reuse:
```json
{
  "detail": "Invalid old password"
}
```

**400 Bad Request** - Password reuse:
```json
{
  "detail": "New password must be different from old password"
}
```

**401 Unauthorized** - Invalid or missing authentication:
```json
{
  "detail": "Invalid authentication credentials"
}
```

**422 Unprocessable Entity** - Password policy violation:
```json
{
  "detail": "Password must be at least 8 characters long"
}
```

**500 Internal Server Error** - Database or system error:
```json
{
  "detail": "An error occurred while changing password"
}
```

## Implementation Details

### Service Layer

The change password functionality is implemented in `UserAuthenticationService.change_password()`:

```python
async def change_password(self, user_id: int, old_password: str, new_password: str) -> None:
    """
    Change a user's password with comprehensive security validation.
    
    Args:
        user_id (int): The ID of the user whose password is being changed.
        old_password (str): The current password for verification.
        new_password (str): The new password to set.
        
    Raises:
        ValueError: If passwords are None or empty.
        AuthenticationError: If user not found or user inactive (401 status).
        InvalidOldPasswordError: If old password is incorrect (400 status).
        PasswordReuseError: If new password is the same as old password (400 status).
        PasswordPolicyError: If new password doesn't meet security policy requirements (422 status).
    """
```

### Security Validation Flow

1. **Input Validation**: Check for None/empty passwords
2. **User Retrieval**: Get user from database by ID
3. **User Status Check**: Verify user exists and is active
4. **Old Password Verification**: Verify current password using bcrypt
5. **Password Reuse Check**: Ensure new password differs from old
6. **Password Policy Validation**: Validate new password against security requirements
7. **Password Hashing**: Securely hash new password with bcrypt
8. **Database Update**: Commit changes to database
9. **Audit Logging**: Log successful password change

### Exception Handling

The API uses specific exception types to return appropriate HTTP status codes:

- `AuthenticationError` → 401 Unauthorized
- `InvalidOldPasswordError` → 400 Bad Request  
- `PasswordReuseError` → 400 Bad Request
- `PasswordPolicyError` → 422 Unprocessable Entity
- `DatabaseError` → 500 Internal Server Error

## Internationalization (I18N)

The API supports multilingual error messages through the i18n system:

### Supported Languages
- English (en)
- Spanish (es) 
- Arabic (ar)
- Persian (fa)

### Error Message Keys
- `password_changed_successfully`: Success message
- `invalid_old_password`: Old password validation error
- `new_password_must_be_different`: Password reuse error
- `password_too_short`: Minimum length error
- `password_no_uppercase`: Missing uppercase error
- `password_no_lowercase`: Missing lowercase error
- `password_no_digit`: Missing digit error
- `password_no_special_char`: Missing special character error

## Usage Examples

### Basic Password Change

```bash
curl -X PUT http://localhost:8000/api/v1/auth/change-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d '{
    "old_password": "CurrentPass123!",
    "new_password": "NewSecurePass456!"
  }'
```

### With Language Preference

```bash
curl -X PUT http://localhost:8000/api/v1/auth/change-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Accept-Language: es" \
  -d '{
    "old_password": "ContraseñaActual123!",
    "new_password": "NuevaContraseñaSegura456!"
  }'
```

### Error Handling Examples

**Weak Password**:
```bash
curl -X PUT http://localhost:8000/api/v1/auth/change-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d '{
    "old_password": "CurrentPass123!",
    "new_password": "weak"
  }'
```

Response:
```json
{
  "detail": "Password must be at least 8 characters long"
}
```

**Invalid Old Password**:
```bash
curl -X PUT http://localhost:8000/api/v1/auth/change-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d '{
    "old_password": "WrongPassword123!",
    "new_password": "NewSecurePass456!"
  }'
```

Response:
```json
{
  "detail": "Invalid old password"
}
```

## Testing

### Unit Tests

Comprehensive unit tests are located in `tests/unit/services/auth/test_change_password.py`:

- **Success Scenarios**: Valid password changes
- **Security Validation**: Old password verification
- **Password Policy**: Policy enforcement testing
- **Error Handling**: All exception scenarios
- **Edge Cases**: Empty passwords, None values
- **Database Errors**: Connection failures

### Integration Tests

Integration tests in `tests/feature/auth/test_change_password_api.py` cover:

- **API Endpoint Testing**: Full request/response cycles
- **Authentication**: Token validation
- **I18N Support**: Multilingual error messages
- **Security Headers**: CORS and security headers
- **Real-world Scenarios**: Various usage patterns
- **Error Scenarios**: All HTTP status codes

### Test Coverage

The change password functionality has comprehensive test coverage including:

- **Unit Tests**: 15 test cases covering all service methods
- **Integration Tests**: 14 test cases covering API endpoints
- **Security Tests**: SQL injection, XSS, and input validation
- **I18N Tests**: Multilingual error message validation
- **Performance Tests**: Database and service performance

## Security Considerations

### Best Practices Implemented

1. **Password Hashing**: Uses bcrypt with configurable work factor
2. **Input Validation**: Comprehensive validation of all inputs
3. **SQL Injection Protection**: Parameterized queries throughout
4. **Rate Limiting**: Integrated with existing rate limiting system
5. **Audit Logging**: All password changes logged for security monitoring
6. **Session Management**: Proper session validation
7. **Error Handling**: Secure error messages without information leakage

### Security Headers

The API includes security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`

### Monitoring and Logging

All password change events are logged with structured logging:

```json
{
  "event": "password_changed",
  "user_id": 123,
  "username": "testuser",
  "timestamp": "2024-01-15T10:30:00Z",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0..."
}
```

## Integration with Existing Systems

### Authentication Flow

The change password API integrates seamlessly with the existing authentication system:

1. **Token Validation**: Uses existing JWT token validation
2. **User Retrieval**: Leverages existing user entity and repository
3. **Password Hashing**: Uses same bcrypt configuration as registration
4. **Session Management**: Integrates with existing session tracking
5. **Rate Limiting**: Uses existing rate limiting infrastructure

### Database Schema

No additional database schema changes are required. The API uses the existing `users` table:

```sql
-- Existing users table structure
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Troubleshooting

### Common Issues

1. **401 Unauthorized**: Check JWT token validity and expiration
2. **400 Bad Request**: Verify old password is correct
3. **422 Unprocessable Entity**: Ensure new password meets policy requirements
4. **500 Internal Server Error**: Check database connectivity and logs

### Debugging

Enable debug logging by setting `LOG_LEVEL=DEBUG` in environment variables:

```bash
export LOG_LEVEL=DEBUG
```

### Log Analysis

Monitor password change events in application logs:

```bash
docker logs cedrina_app_1 | grep "password_changed"
```

## Performance Considerations

### Optimization Features

1. **Async Operations**: All database operations are asynchronous
2. **Connection Pooling**: Uses SQLAlchemy connection pooling
3. **Minimal Queries**: Optimized to use minimal database queries
4. **Caching**: Integrates with existing Redis caching layer

### Benchmarks

Typical performance metrics:
- **Response Time**: < 100ms for successful password changes
- **Database Queries**: 2-3 queries per password change
- **Memory Usage**: Minimal memory footprint
- **Concurrent Users**: Supports high concurrency with connection pooling

## Future Enhancements

### Planned Features

1. **Password History**: Prevent reuse of recent passwords
2. **Two-Factor Authentication**: Require 2FA for password changes
3. **Password Expiration**: Force password changes after time period
4. **Admin Password Reset**: Allow admins to reset user passwords
5. **Password Strength Meter**: Real-time password strength feedback

### Extension Points

The implementation is designed for easy extension:
- **Custom Password Policies**: Configurable policy requirements
- **Additional Validation**: Easy to add new validation rules
- **Notification System**: Integration with email/SMS notifications
- **Audit Trail**: Enhanced logging and monitoring capabilities 