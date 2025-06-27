# Rate Limiting System User Guide

## Overview

The Cedrina rate limiting system provides comprehensive protection against API abuse, DoS attacks, and resource exhaustion. This guide explains how to enable, disable, and configure rate limiting for your application.

## Quick Start

### 1. Enable Rate Limiting

Rate limiting is **enabled by default**. To ensure it's active, set the following environment variable:

```bash
RATE_LIMITING_ENABLED=true
```

### 2. Basic Configuration

Add these environment variables to your `.env` file:

```bash
# Enable rate limiting
RATE_LIMITING_ENABLED=true

# Redis connection (required for distributed rate limiting)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password

# Default limits
RATE_LIMIT_FREE_TIER=60
RATE_LIMIT_PREMIUM_TIER=300
RATE_LIMIT_API_TIER=1000

# Authentication endpoint protection
RATE_LIMIT_AUTH_ENDPOINT=10
RATE_LIMIT_REGISTRATION=3
```

## Configuration Options

### Global Enable/Disable

#### Enable Rate Limiting
```bash
RATE_LIMITING_ENABLED=true
```

#### Disable Rate Limiting Globally
```bash
# Method 1: Set enabled to false
RATE_LIMITING_ENABLED=false

# Method 2: Use disable flag
RATE_LIMITING_DISABLED=true

# Method 3: Emergency disable (highest priority)
RATE_LIMITING_EMERGENCY_DISABLE=true
```

### Granular Bypass Configuration

#### Disable for Specific IP Addresses
```bash
# Single IP
RATE_LIMITING_DISABLE_IPS=192.168.1.100

# Multiple IPs (comma-separated)
RATE_LIMITING_DISABLE_IPS=192.168.1.100,10.0.0.50,172.16.0.25
```

#### Disable for Specific Users
```bash
# Single user
RATE_LIMITING_DISABLE_USERS=admin

# Multiple users (comma-separated)
RATE_LIMITING_DISABLE_USERS=admin,test_user,monitoring_bot
```

#### Disable for Specific Endpoints
```bash
# Single endpoint
RATE_LIMITING_DISABLE_ENDPOINTS=/api/v1/health

# Multiple endpoints (comma-separated)
RATE_LIMITING_DISABLE_ENDPOINTS=/api/v1/health,/api/v1/metrics,/api/v1/status
```

#### Disable for User Tiers
```bash
# Single tier
RATE_LIMITING_DISABLE_TIERS=premium

# Multiple tiers (comma-separated)
RATE_LIMITING_DISABLE_TIERS=premium,enterprise,admin
```

### Rate Limit Configuration

#### Tier-Based Limits (requests per minute)
```bash
# Free tier users
RATE_LIMIT_FREE_TIER=60

# Premium tier users
RATE_LIMIT_PREMIUM_TIER=300

# API tier users
RATE_LIMIT_API_TIER=1000
```

#### Endpoint-Specific Limits
```bash
# Authentication endpoints (login/register)
RATE_LIMIT_AUTH_ENDPOINT=10

# User registration
RATE_LIMIT_REGISTRATION=3
```

#### Algorithm Configuration
```bash
# Choose rate limiting algorithm
RATE_LIMITING_ALGORITHM=token_bucket  # Options: token_bucket, sliding_window, fixed_window
```

#### Resilience Configuration
```bash
# Fail open on errors (allow requests if rate limiting fails)
RATE_LIMITING_FAIL_OPEN=true

# Cache TTL for policies (seconds)
RATE_LIMITING_CACHE_TTL=300
```

## Usage Examples

### Scenario 1: Development Environment

For development, you might want to disable rate limiting entirely:

```bash
# .env for development
RATE_LIMITING_ENABLED=false
REDIS_HOST=localhost
REDIS_PORT=6379
```

### Scenario 2: Production with Monitoring Bypass

In production, you might want to bypass rate limiting for monitoring systems:

```bash
# .env for production
RATE_LIMITING_ENABLED=true
RATE_LIMITING_DISABLE_IPS=10.0.0.50,10.0.0.51
RATE_LIMITING_DISABLE_USERS=monitoring_bot,health_check
RATE_LIMITING_DISABLE_ENDPOINTS=/api/v1/health,/api/v1/metrics
RATE_LIMIT_FREE_TIER=30
RATE_LIMIT_PREMIUM_TIER=200
RATE_LIMIT_API_TIER=500
```

### Scenario 3: Emergency Maintenance

During maintenance or incidents, you can quickly disable rate limiting:

```bash
# Emergency disable (takes precedence over all other settings)
RATE_LIMITING_EMERGENCY_DISABLE=true
```

### Scenario 4: Testing Environment

For testing, you might want very low limits to test rate limiting behavior:

```bash
# .env for testing
RATE_LIMITING_ENABLED=true
RATE_LIMIT_FREE_TIER=5
RATE_LIMIT_PREMIUM_TIER=10
RATE_LIMIT_API_TIER=20
RATE_LIMIT_AUTH_ENDPOINT=2
RATE_LIMIT_REGISTRATION=1
```

## Configuration Priority

The system follows this priority order for bypass decisions:

1. **Emergency Disable** (`RATE_LIMITING_EMERGENCY_DISABLE=true`) - Highest priority
2. **Global Disable** (`RATE_LIMITING_DISABLED=true`)
3. **Enable Flag** (`RATE_LIMITING_ENABLED=false`)
4. **IP-based bypass** (`RATE_LIMITING_DISABLE_IPS`)
5. **User-based bypass** (`RATE_LIMITING_DISABLE_USERS`)
6. **Endpoint-based bypass** (`RATE_LIMITING_DISABLE_ENDPOINTS`)
7. **Tier-based bypass** (`RATE_LIMITING_DISABLE_TIERS`)

## Monitoring and Observability

### Check Rate Limiting Status

The system provides several ways to monitor rate limiting:

1. **Health Check Endpoint**: `/api/v1/health` includes rate limiting status
2. **Metrics Endpoint**: `/api/v1/metrics` (requires admin access) shows rate limiting metrics
3. **Logs**: Rate limiting decisions are logged with detailed information

### Key Metrics to Monitor

- `rate_limit_requests_total`: Total number of rate limit checks
- `rate_limit_requests_allowed`: Number of allowed requests
- `rate_limit_requests_denied`: Number of denied requests
- `rate_limit_latency_seconds`: Rate limiting check latency

### Log Examples

```
INFO: Rate limit check for key=user_123:/api/test:127.0.0.1:default::0b20d0cd, allowed=True, remaining=9, reset_time=2025-06-27 14:01:00
INFO: Rate limit bypassed for IP: 192.168.1.100 (IP-based bypass)
INFO: Rate limiting globally disabled via RATE_LIMITING_DISABLED
```

## Troubleshooting

### Common Issues

#### Rate Limiting Not Working

1. **Check Redis Connection**:
   ```bash
   # Test Redis connectivity
   redis-cli ping
   ```

2. **Verify Environment Variables**:
   ```bash
   # Check if rate limiting is enabled
   echo $RATE_LIMITING_ENABLED
   ```

3. **Check Logs**:
   ```bash
   # Look for rate limiting logs
   grep "rate_limit" /var/log/application.log
   ```

#### Unexpected Rate Limit Denials

1. **Check Bypass Configuration**:
   - Verify IP addresses in `RATE_LIMITING_DISABLE_IPS`
   - Check user IDs in `RATE_LIMITING_DISABLE_USERS`
   - Confirm endpoints in `RATE_LIMITING_DISABLE_ENDPOINTS`

2. **Verify Tier Configuration**:
   - Ensure user tiers are correctly set
   - Check tier-based limits

#### Performance Issues

1. **Monitor Redis Performance**:
   ```bash
   # Check Redis memory usage
   redis-cli info memory
   
   # Check Redis latency
   redis-cli --latency
   ```

2. **Adjust Cache TTL**:
   ```bash
   # Increase cache TTL for better performance
   RATE_LIMITING_CACHE_TTL=600
   ```

### Emergency Procedures

#### Quick Disable
```bash
# Set emergency disable
export RATE_LIMITING_EMERGENCY_DISABLE=true

# Restart application
systemctl restart your-application
```

#### Redis Failure Handling
The system automatically falls back to in-memory rate limiting if Redis is unavailable. Check logs for fallback messages:

```
WARNING: Redis unavailable, falling back to in-memory rate limiting
```

## Best Practices

### Security
1. **Never disable rate limiting in production** without a specific reason
2. **Use specific bypass rules** instead of global disable when possible
3. **Monitor bypass usage** to detect potential abuse
4. **Regularly review bypass lists** and remove unnecessary entries

### Performance
1. **Use appropriate limits** for your application's capacity
2. **Monitor rate limiting latency** to ensure it doesn't impact user experience
3. **Configure Redis properly** for your expected load
4. **Use tier-based limits** to provide better service to premium users

### Operations
1. **Test rate limiting** in staging environments before production
2. **Document bypass procedures** for emergency situations
3. **Set up alerts** for rate limiting failures or unusual patterns
4. **Regularly review and update** rate limiting policies

## Advanced Configuration

### Custom Policies

For advanced use cases, you can define custom rate limiting policies programmatically:

```python
from src.domain.rate_limiting.entities import RateLimitPolicy
from src.domain.rate_limiting.value_objects import RateLimitQuota, RateLimitAlgorithm

# Create custom policy
custom_policy = RateLimitPolicy(
    algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
    name="custom_api_limit",
    user_tiers=["api"],
    priority=50
)
custom_policy.add_quota("user", RateLimitQuota(
    max_requests=500,
    window_seconds=60,
    burst_allowance=50
))
```

### Integration with Application Code

Rate limiting is automatically applied to all API endpoints. For custom integration:

```python
from src.domain.rate_limiting.services import AdvancedRateLimiter
from src.domain.rate_limiting.entities import RateLimitRequest

# Create rate limit request
request = RateLimitRequest(
    user_id="user_123",
    endpoint="/api/v1/data",
    client_ip="192.168.1.100",
    user_tier="premium"
)

# Check rate limit
result = await rate_limiter.check_rate_limit(request)
if not result.allowed:
    raise HTTPException(status_code=429, detail="Rate limit exceeded")
```

## Support

For issues or questions about rate limiting:

1. **Check the logs** for detailed error messages
2. **Review this documentation** for configuration options
3. **Test in isolation** to reproduce the issue
4. **Contact the development team** with specific error messages and configuration details

## Related Documentation

- [Advanced Rate Limiting System](./advanced_rate_limiting_system.md) - Technical architecture and implementation details
- [Real-World Scenarios](./real_world_scenarios.md) - Common use cases and examples
- [Disable Functionality](./disable_functionality.md) - Detailed bypass configuration 