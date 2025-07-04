# Authentication

Cedrina provides a robust authentication system with:

- Username/password authentication (bcrypt hashed)
- OAuth 2.0 (Google, Microsoft, Facebook)
- JWT access and refresh tokens (RS256)
- Secure session management
- Password reset and change flows
- Rate limiting for authentication endpoints

## Key Endpoints
- `POST /api/v1/auth/register` - Register a new user
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/oauth` - OAuth login
- `DELETE /api/v1/auth/logout` - Logout
- `PUT /api/v1/auth/change-password` - Change password
- `POST /api/v1/auth/forgot-password` - Request password reset
- `POST /api/v1/auth/reset-password` - Reset password

## Domain Logic
- See `src/domain/services/authentication/` for core authentication logic
- See `src/domain/value_objects/` for password, email, and token value objects

... (Content to be expanded) ... 