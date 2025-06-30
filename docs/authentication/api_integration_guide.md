# API Integration Guide for Enhanced Session Management

## Overview

This guide provides comprehensive instructions for integrating the enhanced session management features into your API endpoints and client applications.

## Key Changes

### 1. Automatic Session Activity Tracking
All authenticated API endpoints now automatically update session activity when tokens are validated.

### 2. Enhanced Token Validation
Access token validation now includes comprehensive session validation (inactivity timeout, revocation status, etc.).

### 3. Session Limit Enforcement
Users are automatically limited to a configurable number of concurrent sessions.

### 4. Immediate Token Blacklisting
Revoked sessions immediately invalidate associated access tokens.

## API Endpoint Integration

### 1. Authentication Endpoints

#### Login Endpoint
```python
from fastapi import APIRouter, Depends, HTTPException
from src.domain.services.auth.token import TokenService
from src.domain.services.auth.session import SessionService

router = APIRouter()

@router.post("/login")
async def login(
    credentials: LoginRequest,
    token_service: TokenService = Depends(get_token_service),
    session_service: SessionService = Depends(get_session_service)
):
    """Enhanced login with session management."""
    # Authenticate user
    user = await authenticate_user(credentials)
    
    # Create tokens with enhanced session management
    access_token = await token_service.create_access_token(user)
    refresh_token = await token_service.create_refresh_token(user)
    
    # Session activity is automatically tracked during token creation
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }
```

#### Refresh Token Endpoint
```python
@router.post("/refresh")
async def refresh_tokens(
    refresh_request: RefreshRequest,
    token_service: TokenService = Depends(get_token_service)
):
    """Enhanced token refresh with activity tracking."""
    # This now includes automatic session activity tracking
    result = await token_service.refresh_tokens(
        refresh_request.refresh_token,
        refresh_request.language or "en"
    )
    
    return result
```

#### Logout Endpoint
```python
@router.post("/logout")
async def logout(
    logout_request: LogoutRequest,
    current_user: User = Depends(get_current_user),
    token_service: TokenService = Depends(get_token_service)
):
    """Enhanced logout with immediate token invalidation."""
    # Extract JTI from access token
    jti = extract_jti_from_token(logout_request.access_token)
    
    # Revoke session (this also blacklists the access token)
    await token_service.session_service.revoke_session(
        jti, 
        current_user.id, 
        logout_request.language or "en"
    )
    
    return {"message": "Logged out successfully"}
```

### 2. Protected Endpoints

#### Standard Protected Endpoint
```python
@router.get("/protected")
async def protected_endpoint(
    current_user: User = Depends(get_current_user)
):
    """Standard protected endpoint with automatic session validation."""
    # Session validation happens automatically in get_current_user dependency
    return {"message": f"Hello {current_user.username}!"}
```

#### Custom Session Activity Tracking
```python
@router.post("/api/v1/data")
async def update_data(
    data: DataUpdate,
    current_user: User = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service)
):
    """Endpoint with custom session activity tracking."""
    # Extract JTI from request headers or token
    jti = extract_jti_from_request(request)
    
    # Manually update session activity (optional - happens automatically)
    await session_service.update_session_activity(jti, current_user.id)
    
    # Process data update
    result = await process_data_update(data, current_user)
    
    return result
```

## Dependency Injection Setup

### 1. Enhanced Auth Dependencies

```python
# src/core/dependencies/auth.py
from fastapi import Depends, HTTPException, status
from src.domain.services.auth.token import TokenService
from src.domain.services.auth.session import SessionService

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    token_service: TokenService = Depends(get_token_service)
) -> User:
    """Enhanced current user dependency with session validation."""
    try:
        # This now includes comprehensive session validation
        payload = await token_service.validate_token(token)
        user_id = int(payload["sub"])
        
        # Get user from database
        user = await get_user_by_id(user_id)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User is invalid or inactive"
            )
        
        return user
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )

async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Ensure user is active."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user
```

### 2. Session Service Dependencies

```python
# src/infrastructure/dependency_injection/session_dependencies.py
from fastapi import Depends
from src.domain.services.auth.session import SessionService
from src.infrastructure.database.database import get_session
from src.infrastructure.redis import get_redis_client

async def get_session_service(
    db_session = Depends(get_session),
    redis_client = Depends(get_redis_client)
) -> SessionService:
    """Provide SessionService instance."""
    return SessionService(db_session, redis_client)
```

## Client-Side Integration

### 1. JavaScript/TypeScript Client

```typescript
// session-manager.ts
class SessionManager {
    private accessToken: string | null = null;
    private refreshToken: string | null = null;
    private inactivityTimer: NodeJS.Timeout | null = null;
    
    constructor(private apiBaseUrl: string) {}
    
    async login(username: string, password: string): Promise<void> {
        const response = await fetch(`${this.apiBaseUrl}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        if (!response.ok) {
            throw new Error('Login failed');
        }
        
        const data = await response.json();
        this.accessToken = data.access_token;
        this.refreshToken = data.refresh_token;
        
        // Start inactivity timer
        this.startInactivityTimer();
        
        // Store tokens securely
        this.storeTokens();
    }
    
    async refreshTokens(): Promise<void> {
        if (!this.refreshToken) {
            throw new Error('No refresh token available');
        }
        
        const response = await fetch(`${this.apiBaseUrl}/auth/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                refresh_token: this.refreshToken,
                language: navigator.language.split('-')[0]
            })
        });
        
        if (!response.ok) {
            // Refresh failed, redirect to login
            this.logout();
            throw new Error('Token refresh failed');
        }
        
        const data = await response.json();
        this.accessToken = data.access_token;
        this.refreshToken = data.refresh_token;
        
        // Reset inactivity timer
        this.startInactivityTimer();
        this.storeTokens();
    }
    
    async logout(): Promise<void> {
        if (this.accessToken) {
            try {
                await fetch(`${this.apiBaseUrl}/auth/logout`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.accessToken}`
                    },
                    body: JSON.stringify({ 
                        access_token: this.accessToken,
                        language: navigator.language.split('-')[0]
                    })
                });
            } catch (error) {
                console.warn('Logout request failed:', error);
            }
        }
        
        this.clearTokens();
        this.stopInactivityTimer();
    }
    
    private startInactivityTimer(): void {
        this.stopInactivityTimer();
        
        // Set timer for 25 minutes (5 minutes before server timeout)
        this.inactivityTimer = setTimeout(() => {
            this.logout();
        }, 25 * 60 * 1000);
    }
    
    private stopInactivityTimer(): void {
        if (this.inactivityTimer) {
            clearTimeout(this.inactivityTimer);
            this.inactivityTimer = null;
        }
    }
    
    private storeTokens(): void {
        // Store tokens securely (consider using httpOnly cookies in production)
        localStorage.setItem('access_token', this.accessToken!);
        localStorage.setItem('refresh_token', this.refreshToken!);
    }
    
    private clearTokens(): void {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        this.accessToken = null;
        this.refreshToken = null;
    }
    
    // API request wrapper with automatic token refresh
    async apiRequest(url: string, options: RequestInit = {}): Promise<Response> {
        if (!this.accessToken) {
            throw new Error('No access token available');
        }
        
        const response = await fetch(url, {
            ...options,
            headers: {
                ...options.headers,
                'Authorization': `Bearer ${this.accessToken}`
            }
        });
        
        if (response.status === 401) {
            // Token expired, try to refresh
            try {
                await this.refreshTokens();
                
                // Retry request with new token
                return fetch(url, {
                    ...options,
                    headers: {
                        ...options.headers,
                        'Authorization': `Bearer ${this.accessToken}`
                    }
                });
            } catch (error) {
                // Refresh failed, redirect to login
                this.logout();
                throw error;
            }
        }
        
        return response;
    }
}
```

### 2. React Hook Example

```typescript
// useSession.ts
import { useState, useEffect, useCallback } from 'react';
import { SessionManager } from './session-manager';

export function useSession() {
    const [sessionManager] = useState(() => new SessionManager('/api/v1'));
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [user, setUser] = useState(null);
    
    const login = useCallback(async (username: string, password: string) => {
        try {
            await sessionManager.login(username, password);
            setIsAuthenticated(true);
            
            // Fetch user profile
            const response = await sessionManager.apiRequest('/api/v1/auth/profile');
            const userData = await response.json();
            setUser(userData);
        } catch (error) {
            throw error;
        }
    }, [sessionManager]);
    
    const logout = useCallback(async () => {
        await sessionManager.logout();
        setIsAuthenticated(false);
        setUser(null);
    }, [sessionManager]);
    
    const apiRequest = useCallback(async (url: string, options?: RequestInit) => {
        return sessionManager.apiRequest(url, options);
    }, [sessionManager]);
    
    useEffect(() => {
        // Check if user is already authenticated on mount
        const token = localStorage.getItem('access_token');
        if (token) {
            setIsAuthenticated(true);
            // Fetch user profile
            sessionManager.apiRequest('/api/v1/auth/profile')
                .then(response => response.json())
                .then(userData => setUser(userData))
                .catch(() => {
                    // Token invalid, clear authentication
                    setIsAuthenticated(false);
                    sessionManager.clearTokens();
                });
        }
    }, [sessionManager]);
    
    return {
        isAuthenticated,
        user,
        login,
        logout,
        apiRequest
    };
}
```

## Error Handling

### 1. Session-Related Error Responses

```python
# Error response examples
{
    "detail": "Session expired due to inactivity",
    "code": "session_inactivity_timeout"
}

{
    "detail": "Maximum number of concurrent sessions exceeded",
    "code": "session_limit_exceeded"
}

{
    "detail": "Session has been revoked or is invalid",
    "code": "session_revoked_or_invalid"
}

{
    "detail": "Access token has been revoked",
    "code": "access_token_blacklisted"
}
```

### 2. Client-Side Error Handling

```typescript
// error-handler.ts
export class SessionErrorHandler {
    static handleError(error: any, sessionManager: SessionManager): void {
        if (error.code === 'session_inactivity_timeout') {
            // Session expired due to inactivity
            sessionManager.logout();
            // Redirect to login with message
            window.location.href = '/login?message=session_expired';
        } else if (error.code === 'session_limit_exceeded') {
            // User has too many active sessions
            alert('You have too many active sessions. Please log out from other devices.');
        } else if (error.code === 'session_revoked_or_invalid') {
            // Session was revoked
            sessionManager.logout();
            window.location.href = '/login?message=session_revoked';
        } else if (error.code === 'access_token_blacklisted') {
            // Access token was blacklisted
            sessionManager.logout();
            window.location.href = '/login?message=token_revoked';
        }
    }
}
```

## Monitoring and Debugging

### 1. Session Monitoring Endpoints

```python
@router.get("/admin/sessions/active")
async def get_active_sessions(
    current_user: User = Depends(get_current_admin_user),
    session_service: SessionService = Depends(get_session_service)
):
    """Get active sessions for current user (admin only)."""
    sessions = await session_service.get_user_active_sessions(current_user.id)
    return {
        "user_id": current_user.id,
        "active_sessions": len(sessions),
        "sessions": [
            {
                "jti": session.jti,
                "created_at": session.created_at,
                "last_activity": session.last_activity_at,
                "expires_at": session.expires_at
            }
            for session in sessions
        ]
    }

@router.post("/admin/sessions/cleanup")
async def cleanup_sessions(
    current_user: User = Depends(get_current_admin_user),
    session_service: SessionService = Depends(get_session_service)
):
    """Clean up expired sessions (admin only)."""
    count = await session_service.cleanup_expired_sessions()
    return {"cleaned_sessions": count}
```

### 2. Debug Headers

```python
# Add debug headers to responses
@router.get("/debug/session-info")
async def get_session_info(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Get current session information for debugging."""
    jti = extract_jti_from_request(request)
    
    return {
        "user_id": current_user.id,
        "jti": jti,
        "session_valid": await session_service.is_session_valid(jti, current_user.id),
        "active_sessions": len(await session_service.get_user_active_sessions(current_user.id))
    }
```

## Best Practices

### 1. Security Considerations

- **Token Storage**: Use httpOnly cookies for production applications
- **HTTPS Only**: Always use HTTPS in production
- **Token Rotation**: Implement automatic token rotation on refresh
- **Session Monitoring**: Monitor for unusual session patterns

### 2. Performance Considerations

- **Caching**: Cache user data to reduce database queries
- **Batch Operations**: Use batch operations for session cleanup
- **Connection Pooling**: Ensure proper database and Redis connection pooling

### 3. User Experience

- **Graceful Degradation**: Handle session expiration gracefully
- **Clear Messaging**: Provide clear error messages to users
- **Automatic Refresh**: Implement automatic token refresh before expiration

## Migration Guide

### 1. Existing API Endpoints

For existing endpoints, the enhanced session management is mostly transparent:

```python
# Before (still works)
@router.get("/api/v1/data")
async def get_data(current_user: User = Depends(get_current_user)):
    return {"data": "some data"}

# After (enhanced with session validation)
@router.get("/api/v1/data")
async def get_data(current_user: User = Depends(get_current_user)):
    # Session validation happens automatically
    return {"data": "some data"}
```

### 2. Custom Session Logic

If you have custom session logic, update it to use the new methods:

```python
# Before
session = await session_service.get_session(jti, user_id)
if not session or session.revoked_at:
    raise HTTPException(status_code=401, detail="Invalid session")

# After
if not await session_service.is_session_valid(jti, user_id):
    raise HTTPException(status_code=401, detail="Invalid session")

# Update activity (optional - happens automatically)
await session_service.update_session_activity(jti, user_id)
```

## Testing

### 1. Unit Tests

```python
# test_session_integration.py
@pytest.mark.asyncio
async def test_protected_endpoint_with_session_validation():
    # Create user and session
    user = create_test_user()
    session = await create_test_session(user)
    
    # Create access token
    token = create_access_token(user, session.jti)
    
    # Test protected endpoint
    response = await client.get(
        "/api/v1/protected",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200
    
    # Verify session activity was updated
    updated_session = await get_session(session.jti, user.id)
    assert updated_session.last_activity_at > session.last_activity_at
```

### 2. Integration Tests

```python
# test_session_flow.py
@pytest.mark.asyncio
async def test_complete_session_flow():
    # 1. Login
    login_response = await client.post("/auth/login", json={
        "username": "testuser",
        "password": "testpass"
    })
    assert login_response.status_code == 200
    
    tokens = login_response.json()
    
    # 2. Use protected endpoint
    protected_response = await client.get(
        "/api/v1/protected",
        headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert protected_response.status_code == 200
    
    # 3. Refresh tokens
    refresh_response = await client.post("/auth/refresh", json={
        "refresh_token": tokens["refresh_token"]
    })
    assert refresh_response.status_code == 200
    
    # 4. Logout
    logout_response = await client.post("/auth/logout", json={
        "access_token": tokens["access_token"]
    })
    assert logout_response.status_code == 200
    
    # 5. Verify token is blacklisted
    invalid_response = await client.get(
        "/api/v1/protected",
        headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert invalid_response.status_code == 401
```

## Troubleshooting

### Common Issues

1. **Session Creation Timeouts**
   - Check Redis connectivity
   - Verify database performance
   - Adjust `SESSION_CONSISTENCY_TIMEOUT_SECONDS`

2. **High Session Revocation Rates**
   - Review inactivity timeout settings
   - Check client-side session management
   - Monitor for security incidents

3. **Token Validation Failures**
   - Verify JWT configuration
   - Check session database consistency
   - Review blacklist TTL settings

### Debug Commands

```bash
# Check session status
curl -H "Authorization: Bearer <token>" http://localhost:8000/debug/session-info

# Monitor sessions
/usr/local/bin/monitor_sessions.sh

# Check Redis blacklist
redis-cli keys "access_token_blacklist:*" | wc -l

# Check database sessions
psql -c "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL;"
``` 