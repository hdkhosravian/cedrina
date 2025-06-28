# Authentication Documentation

This directory contains comprehensive documentation for the Cedrina Authentication System, a robust, secure, and scalable authentication solution built with FastAPI, SQLModel, and PostgreSQL.

## Documentation Files

### Core Documentation

- **[complete_authentication_system.md](complete_authentication_system.md)** - Comprehensive overview of the entire authentication system, including architecture, components, security mechanisms, and usage examples.

- **[services.md](services.md)** - Detailed documentation of authentication services including UserAuthenticationService, OAuthService, TokenService, and SessionService.

- **[models.md](models.md)** - Documentation of domain entities (User, OAuthProfile, Session) and their database schemas.

- **[setup.md](setup.md)** - Step-by-step setup instructions for the authentication system.

- **[testing.md](testing.md)** - Comprehensive testing strategy, test structure, and execution guidelines.

### Feature-Specific Documentation

- **[change_password_api.md](change_password_api.md)** - Complete documentation for the Change Password API feature, including security features, API specification, implementation details, and testing.

### Security Documentation

- **[security_fixes.md](security_fixes.md)** - Security improvements, fixes, and best practices implemented in the authentication system.

## Quick Start

1. **Setup**: Follow the [setup guide](setup.md) to configure the authentication system
2. **Architecture**: Understand the system design in [complete_authentication_system.md](complete_authentication_system.md)
3. **Services**: Learn about individual services in [services.md](services.md)
4. **Testing**: Run tests following the [testing guide](testing.md)

## Key Features

### Authentication Methods
- **Username/Password**: Traditional authentication with bcrypt hashing
- **OAuth 2.0**: Integration with Google, Microsoft, and Facebook
- **JWT Tokens**: RS256-signed access and refresh tokens
- **Session Management**: Secure session tracking and revocation

### Security Features
- **Password Policy**: Enforced password complexity requirements
- **Rate Limiting**: Protection against brute force attacks
- **Token Encryption**: OAuth tokens encrypted with pgcrypto
- **Audit Logging**: Comprehensive security event logging
- **Change Password API**: Secure password change with old password verification

### API Endpoints
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/oauth` - OAuth authentication
- `DELETE /api/v1/auth/logout` - User logout
- `PUT /api/v1/auth/change-password` - Password change

## Architecture

The authentication system follows Clean Architecture and Domain-Driven Design principles:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   API Layer     │    │  Domain Layer   │    │ Infrastructure  │
│                 │    │                 │    │                 │
│ • FastAPI       │◄──►│ • Services      │◄──►│ • PostgreSQL    │
│ • Dependencies  │    │ • Entities      │    │ • Redis         │
│ • Schemas       │    │ • Value Objects │    │ • OAuth Clients │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Security Standards

The system implements enterprise-grade security practices:

- **Password Hashing**: bcrypt with configurable work factor
- **JWT Signing**: RS256 asymmetric key signing
- **Token Encryption**: pgcrypto for OAuth tokens
- **Input Validation**: Comprehensive Pydantic validation
- **Rate Limiting**: Redis-based rate limiting
- **Audit Logging**: Structured logging for security events

## Testing

Comprehensive test coverage includes:

- **Unit Tests**: 318 test cases covering all components
- **Integration Tests**: End-to-end API testing
- **Security Tests**: SQL injection, XSS, and input validation
- **I18N Tests**: Multilingual error message validation
- **Performance Tests**: Database and service performance

## Getting Help

- **Setup Issues**: Check [setup.md](setup.md) for common configuration problems
- **API Usage**: See examples in [complete_authentication_system.md](complete_authentication_system.md)
- **Testing**: Follow the [testing guide](testing.md)
- **Security**: Review [security_fixes.md](security_fixes.md) for security considerations

## Contributing

When contributing to the authentication system:

1. Follow the established architecture patterns
2. Add comprehensive tests for new features
3. Update relevant documentation
4. Ensure security best practices are maintained
5. Follow the testing strategy outlined in [testing.md](testing.md) 