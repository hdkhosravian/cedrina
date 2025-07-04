# Rate Limiting

Cedrina implements advanced rate limiting to protect against abuse and DoS attacks.

- Multiple algorithms: fixed-window, sliding-window, token-bucket
- Per-user, per-endpoint, and tier-based limits
- Configurable via environment variables and settings
- Integrated with authentication and admin endpoints

## Key Endpoints
- All authentication endpoints are rate-limited
- Admin endpoints have stricter limits

## Domain Logic
- See `src/core/rate_limiting/` for core logic and configuration
- See `src/domain/services/` for rate limiting services

... (Content to be expanded) ... 