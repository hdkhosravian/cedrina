# Rate Limiting Disable Functionality

## Overview

The Cedrina rate limiting system provides multiple levels of bypass functionality to accommodate different operational needs. This document explains all the ways to disable or bypass rate limiting, from global disable to granular bypass rules.

## Disable Methods Overview

The system supports several methods to disable rate limiting, each with different use cases and priority levels:

1. **Emergency Disable** - Highest priority, immediate global disable
2. **Global Disable** - Standard global disable for maintenance
3. **Enable Flag** - Basic enable/disable control
4. **Granular Bypass** - Selective bypass for specific entities

## 1. Emergency Disable

### Purpose
Emergency disable is designed for critical situations where rate limiting must be immediately disabled across the entire system. This takes precedence over all other configuration.

### Configuration
```bash
RATE_LIMITING_EMERGENCY_DISABLE=true
```

### Use Cases
- **System-wide incidents** where rate limiting is causing issues
- **Emergency maintenance** requiring immediate disable
- **Critical bug fixes** where rate limiting interferes with resolution
- **Disaster recovery** scenarios

### Priority
- **Highest priority** - overrides all other settings
- Takes effect immediately upon configuration change
- No restart required (configuration is reloaded dynamically)

### Example
```bash
# Emergency situation - disable immediately
export RATE_LIMITING_EMERGENCY_DISABLE=true
# Application will bypass all rate limiting
```

## 2. Global Disable

### Purpose
Standard method to disable rate limiting globally for planned maintenance or configuration changes.

### Configuration
```bash
RATE_LIMITING_DISABLED=true
```

### Use Cases
- **Planned maintenance** windows
- **System upgrades** where rate limiting might interfere
- **Testing scenarios** requiring global disable
- **Configuration changes** that might affect rate limiting

### Priority
- **High priority** - overrides most other settings
- Takes precedence over enable flag
- Can be overridden by emergency disable

### Example
```bash
# Planned maintenance
RATE_LIMITING_DISABLED=true
RATE_LIMITING_ENABLED=true  # This will be ignored
```

## 3. Enable Flag

### Purpose
Basic enable/disable control for rate limiting functionality.

### Configuration
```bash
# Enable rate limiting (default)
RATE_LIMITING_ENABLED=true

# Disable rate limiting
RATE_LIMITING_ENABLED=false
```

### Use Cases
- **Development environments** where rate limiting is not needed
- **Testing scenarios** requiring simple enable/disable
- **Basic configuration** for simple deployments

### Priority
- **Medium priority** - can be overridden by global disable or emergency disable
- Standard configuration method

### Example
```bash
# Development environment
RATE_LIMITING_ENABLED=false
```

## 4. Granular Bypass Configuration

### Purpose
Selective bypass of rate limiting for specific IP addresses, users, endpoints, or user tiers. This allows rate limiting to remain active while bypassing it for specific entities.

### IP-Based Bypass

#### Configuration
```bash
# Single IP address
RATE_LIMITING_DISABLE_IPS=192.168.1.100

# Multiple IP addresses (comma-separated)
RATE_LIMITING_DISABLE_IPS=192.168.1.100,10.0.0.50,172.16.0.25

# IP ranges (basic support)
RATE_LIMITING_DISABLE_IPS=192.168.1.0/24,10.0.0.0/8
```

#### Use Cases
- **Monitoring systems** that need unrestricted access
- **Load balancers** and reverse proxies
- **Internal services** that require bypass
- **Development machines** for testing

#### Example
```bash
# Bypass for monitoring and internal services
RATE_LIMITING_DISABLE_IPS=10.0.0.50,10.0.0.51,192.168.1.100
```

### User-Based Bypass

#### Configuration
```bash
# Single user
RATE_LIMITING_DISABLE_USERS=admin

# Multiple users (comma-separated)
RATE_LIMITING_DISABLE_USERS=admin,test_user,monitoring_bot,health_check

# Service accounts
RATE_LIMITING_DISABLE_USERS=service_account_1,service_account_2
```

#### Use Cases
- **Administrative users** who need unrestricted access
- **Service accounts** for automated processes
- **Testing users** for development
- **Monitoring bots** and health checks

#### Example
```bash
# Bypass for admin and service accounts
RATE_LIMITING_DISABLE_USERS=admin,monitoring_bot,health_check_service
```

### Endpoint-Based Bypass

#### Configuration
```bash
# Single endpoint
RATE_LIMITING_DISABLE_ENDPOINTS=/api/v1/health

# Multiple endpoints (comma-separated)
RATE_LIMITING_DISABLE_ENDPOINTS=/api/v1/health,/api/v1/metrics,/api/v1/status

# API documentation endpoints
RATE_LIMITING_DISABLE_ENDPOINTS=/docs,/redoc,/openapi.json
```

#### Use Cases
- **Health check endpoints** that need to be always accessible
- **Metrics endpoints** for monitoring
- **Documentation endpoints** that shouldn't be rate limited
- **Status endpoints** for system monitoring

#### Example
```bash
# Bypass for monitoring and documentation endpoints
RATE_LIMITING_DISABLE_ENDPOINTS=/api/v1/health,/api/v1/metrics,/docs,/redoc
```

### Tier-Based Bypass

#### Configuration
```bash
# Single tier
RATE_LIMITING_DISABLE_TIERS=premium

# Multiple tiers (comma-separated)
RATE_LIMITING_DISABLE_TIERS=premium,enterprise,admin

# All premium tiers
RATE_LIMITING_DISABLE_TIERS=premium,enterprise
```

#### Use Cases
- **Premium users** who should not be rate limited
- **Enterprise customers** with special access
- **Administrative tiers** that need bypass
- **VIP users** with unrestricted access

#### Example
```bash
# Bypass for premium and enterprise users
RATE_LIMITING_DISABLE_TIERS=premium,enterprise,admin
```

## Configuration Priority

The system follows a strict priority order when determining whether to bypass rate limiting:

1. **Emergency Disable** (`RATE_LIMITING_EMERGENCY_DISABLE=true`) - **Highest Priority**
2. **Global Disable** (`RATE_LIMITING_DISABLED=true`)
3. **Enable Flag** (`RATE_LIMITING_ENABLED=false`)
4. **IP-based bypass** (`RATE_LIMITING_DISABLE_IPS`)
5. **User-based bypass** (`RATE_LIMITING_DISABLE_USERS`)
6. **Endpoint-based bypass** (`RATE_LIMITING_DISABLE_ENDPOINTS`)
7. **Tier-based bypass** (`RATE_LIMITING_DISABLE_TIERS`)

### Priority Example
```bash
# Configuration
RATE_LIMITING_ENABLED=true
RATE_LIMITING_DISABLED=false
RATE_LIMITING_EMERGENCY_DISABLE=false
RATE_LIMITING_DISABLE_IPS=192.168.1.100
RATE_LIMITING_DISABLE_USERS=admin
RATE_LIMITING_DISABLE_ENDPOINTS=/api/v1/health

# Result: Rate limiting is enabled, but bypassed for:
# - IP 192.168.1.100
# - User 'admin'
# - Endpoint '/api/v1/health'
```

## Configuration Examples

### Development Environment
```bash
# Complete disable for development
RATE_LIMITING_ENABLED=false
REDIS_HOST=localhost
REDIS_PORT=6379
```

### Staging Environment
```bash
# Enable with low limits and bypass for testing
RATE_LIMITING_ENABLED=true
RATE_LIMIT_FREE_TIER=10
RATE_LIMIT_PREMIUM_TIER=20
RATE_LIMITING_DISABLE_USERS=test_user,admin
RATE_LIMITING_DISABLE_ENDPOINTS=/api/v1/health,/api/v1/metrics
```

### Production Environment
```bash
# Production with monitoring bypass
RATE_LIMITING_ENABLED=true
RATE_LIMIT_FREE_TIER=60
RATE_LIMIT_PREMIUM_TIER=300
RATE_LIMIT_API_TIER=1000
RATE_LIMITING_DISABLE_IPS=10.0.0.50,10.0.0.51
RATE_LIMITING_DISABLE_USERS=monitoring_bot,health_check
RATE_LIMITING_DISABLE_ENDPOINTS=/api/v1/health,/api/v1/metrics
RATE_LIMITING_DISABLE_TIERS=enterprise
```

### Emergency Configuration
```bash
# Emergency disable
RATE_LIMITING_EMERGENCY_DISABLE=true
# All other rate limiting settings are ignored
```

## Monitoring and Logging

### Bypass Logging
The system logs all bypass decisions for monitoring and audit purposes:

```
INFO: Rate limiting globally disabled via RATE_LIMITING_DISABLED
INFO: Rate limiting disabled via emergency override (RATE_LIMITING_EMERGENCY_DISABLE)
INFO: Rate limiting disabled for IP: 192.168.1.100
INFO: Rate limiting disabled for user: admin
INFO: Rate limiting disabled for endpoint: /api/v1/health
INFO: Rate limiting disabled for tier: premium
```

### Monitoring Bypass Usage
Monitor bypass usage to detect potential abuse or misconfiguration:

```bash
# Check bypass logs
grep "Rate limiting disabled" /var/log/application.log

# Monitor bypass frequency
grep "Rate limiting disabled" /var/log/application.log | wc -l
```

### Metrics
The system provides metrics for bypass decisions:

- `rate_limit_bypass_total`: Total number of bypassed requests
- `rate_limit_bypass_reason`: Breakdown of bypass reasons

## Security Considerations

### Bypass Security
1. **Minimize bypass usage** - Only bypass when absolutely necessary
2. **Regular review** - Periodically review and remove unnecessary bypasses
3. **Audit logging** - All bypass decisions are logged for audit purposes
4. **Monitoring** - Monitor bypass usage for unusual patterns

### Best Practices
1. **Use specific bypasses** instead of global disable when possible
2. **Document bypass reasons** and review regularly
3. **Set up alerts** for unusual bypass patterns
4. **Test bypass configurations** in staging before production

## Troubleshooting

### Common Issues

#### Bypass Not Working
1. **Check priority order** - Ensure your bypass method has sufficient priority
2. **Verify configuration** - Check environment variable names and values
3. **Check logs** - Look for bypass decision logs
4. **Restart application** - Some configuration changes require restart

#### Unexpected Bypass
1. **Check emergency disable** - `RATE_LIMITING_EMERGENCY_DISABLE` overrides everything
2. **Review global disable** - `RATE_LIMITING_DISABLED` might be set
3. **Check enable flag** - `RATE_LIMITING_ENABLED=false` disables globally
4. **Verify bypass lists** - Check if entity is in bypass lists

### Debug Commands
```bash
# Check current configuration
echo "RATE_LIMITING_ENABLED: $RATE_LIMITING_ENABLED"
echo "RATE_LIMITING_DISABLED: $RATE_LIMITING_DISABLED"
echo "RATE_LIMITING_EMERGENCY_DISABLE: $RATE_LIMITING_EMERGENCY_DISABLE"

# Check bypass lists
echo "RATE_LIMITING_DISABLE_IPS: $RATE_LIMITING_DISABLE_IPS"
echo "RATE_LIMITING_DISABLE_USERS: $RATE_LIMITING_DISABLE_USERS"
echo "RATE_LIMITING_DISABLE_ENDPOINTS: $RATE_LIMITING_DISABLE_ENDPOINTS"
echo "RATE_LIMITING_DISABLE_TIERS: $RATE_LIMITING_DISABLE_TIERS"
```

## Emergency Procedures

### Quick Disable
```bash
# Emergency disable (immediate effect)
export RATE_LIMITING_EMERGENCY_DISABLE=true

# Restart application if needed
systemctl restart your-application
```

### Gradual Re-enable
```bash
# 1. Remove emergency disable
unset RATE_LIMITING_EMERGENCY_DISABLE

# 2. Use global disable for controlled re-enable
export RATE_LIMITING_DISABLED=true

# 3. Gradually remove bypasses
# 4. Finally enable rate limiting
export RATE_LIMITING_DISABLED=false
export RATE_LIMITING_ENABLED=true
```

## Related Documentation

- [Rate Limiting User Guide](./README.md) - General rate limiting configuration
- [Advanced Rate Limiting System](./advanced_rate_limiting_system.md) - Technical implementation details
- [Real-World Scenarios](./real_world_scenarios.md) - Common use cases and examples 