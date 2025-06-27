# Advanced Rate Limiting System Documentation

## Overview

The Advanced Rate Limiting System in the `cedrina` project is a sophisticated mechanism designed to control the rate of requests to various endpoints, ensuring system stability, security, and fair usage. This system is built following **Domain-Driven Design (DDD)** principles, with a focus on clean code, modularity, testability, and performance optimization. It supports multiple rate limiting algorithms, hierarchical limits, resilience patterns, observability, and security features to prevent abuse.

This documentation provides an in-depth look at the system's architecture, components, usage, configuration, testing, and extension points. It is intended for developers, system architects, and DevOps engineers who need to understand, maintain, or extend the rate limiting functionality.

## Purpose and Usage

### Why Rate Limiting?
Rate limiting is critical for modern web applications to:
- **Protect System Resources**: Prevent overload by limiting the number of requests a client or user can make in a given time frame.
- **Ensure Fair Usage**: Distribute resources equitably among users, preventing any single user or client from monopolizing the system.
- **Enhance Security**: Mitigate denial-of-service (DoS) attacks, brute force attempts, and other abusive behaviors.
- **Maintain Performance**: Ensure consistent response times by controlling request spikes.

### Usage Scenarios
The rate limiting system in `cedrina` is used to:
- Protect API endpoints from excessive requests (e.g., login, data retrieval).
- Enforce different limits based on user roles, client IP, or endpoint-specific policies.
- Provide hierarchical limits (e.g., global limits for all users, stricter limits for specific users).
- Monitor and trace rate limiting decisions for debugging and performance analysis.

## System Architecture

The rate limiting system is designed with a **Domain-Driven Design (DDD)** approach, separating concerns into distinct layers and bounded contexts. It is built to be modular, extensible, and highly testable, adhering to clean code principles.

### High-Level Architecture

The system follows a layered architecture:
1. **API Layer** (`src/adapters/api/`): Handles HTTP requests and integrates rate limiting as a middleware or dependency.
2. **Core Layer** (`src/core/`): Contains cross-cutting concerns like configuration and metrics.
3. **Domain Layer** (`src/domain/rate_limiting/`): Encapsulates the core business logic of rate limiting, including entities, value objects, services, and repositories.
4. **Infrastructure Layer** (`src/infrastructure/`): Provides concrete implementations for data storage (Redis) and other external dependencies.

### Key Components

#### 1. Value Objects (`src/domain/rate_limiting/value_objects.py`)
Value objects are immutable structures that represent core concepts in rate limiting:
- **RateLimitKey**: A unique identifier for a rate limit bucket, combining user ID, endpoint, and client IP. Ensures uniqueness and prevents collisions.
- **RateLimitQuota**: Defines the rate limit policy, including maximum requests, time window (in seconds), and burst allowance.
- **RateLimitRequest**: Captures details of an incoming request for rate limiting purposes.
- **RateLimitContext**: Provides contextual information for rate limiting decisions, including applicable policies and hierarchical keys.
- **RateLimitResult**: Represents the outcome of a rate limit check, including whether the request is allowed, remaining requests, and reset time.
- **RateLimitPeriod**: Defines the time period for rate limiting windows.

#### 2. Entities (`src/domain/rate_limiting/entities.py`)
Entities represent stateful objects with identity:
- **RateLimitBucket**: Manages the state of a rate limit bucket for a specific key, tracking request counts or tokens based on the algorithm used.
- **RateLimitPolicy**: Defines a rate limiting policy with a quota, applicable scope (global, user-specific, endpoint-specific), and priority.

#### 3. Services (`src/domain/rate_limiting/services.py`)
Services encapsulate the business logic for rate limiting:
- **RateLimitService**: The primary service for checking rate limits. It coordinates policy resolution, algorithm application, and metrics collection. It supports multiple algorithms (Token Bucket, Sliding Window, Fixed Window) and handles concurrent requests safely.
- **RateLimitPolicyService**: Manages policy CRUD operations and caching, ensuring efficient policy resolution for hierarchical limits.

#### 4. Repositories (`src/domain/rate_limiting/repositories.py`)
Repositories abstract data access and storage:
- **RateLimitRepository (Abstract Base Class)**: Defines the interface for rate limit data operations (e.g., increment counters, get bucket state).
- **RedisRateLimitRepository**: A concrete implementation using Redis for distributed rate limiting. It handles key generation, counter updates, and window management with TTLs for automatic cleanup.

#### 5. Algorithms
The system supports multiple rate limiting algorithms, each with specific characteristics:
- **Token Bucket**: Allows bursts up to a defined limit, refilling tokens over time. Suitable for scenarios requiring burst tolerance.
- **Sliding Window**: Counts requests within a rolling time window, providing accurate rate control.
- **Fixed Window**: Counts requests in fixed time windows, resetting at window boundaries. Simple and efficient for basic rate limiting.

#### 6. Resilience and Observability
- **Circuit Breaker**: Integrated via `src/core/circuit_breaker.py` to prevent cascading failures when Redis is unavailable.
- **Metrics**: Integrated with `src/core/metrics.py` to collect detailed statistics on rate limit decisions (e.g., allowed/denied requests, latency).
- **Distributed Tracing**: Supports tracing rate limit checks to analyze performance bottlenecks.

## Configuration

### Environment Variables
Rate limiting configuration is managed through environment variables in `src/core/config/settings.py`:
- `RATE_LIMIT_ENABLED`: Boolean flag to enable/disable rate limiting globally.
- `REDIS_URL`: Connection string for Redis, used for distributed rate limiting.
- `RATE_LIMIT_DEFAULT_MAX_REQUESTS`: Default maximum requests per window if no policy is specified.
- `RATE_LIMIT_DEFAULT_WINDOW_SECONDS`: Default time window in seconds.

### Policy Configuration
Policies can be defined programmatically or loaded from configuration files. Each policy specifies:
- Scope (global, user-specific, endpoint-specific)
- Quota (max requests, window duration, burst allowance)
- Priority for hierarchical resolution

Example policy definition:
```python
policy = RateLimitPolicy(
    name="login_endpoint_limit",
    quota=RateLimitQuota(max_requests=10, window_seconds=60, burst_allowance=2),
    scope={"endpoint": "/api/auth/login"},
    priority=5
)
```

## Integration with FastAPI

Rate limiting is integrated into the FastAPI application as a middleware or dependency:
1. **Middleware**: Applies global rate limits to all requests.
2. **Dependency**: Allows endpoint-specific rate limits via FastAPI's dependency injection.

Example dependency usage in `src/adapters/api/v1/auth/routes/login.py`:
```python
@router.post("/login", response_model=TokenResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    rate_limit_service: RateLimitService = Depends(get_rate_limit_service)
):
    # Rate limit check
    context = RateLimitContext.from_request(request)
    result = await rate_limit_service.check_rate_limit(context)
    if not result.allowed:
        raise RateLimitExceededError()
    # Proceed with login logic
```

## Security Features

The rate limiting system includes several security mechanisms:
- **Sophisticated Key Generation**: Combines multiple identifiers (user ID, IP, endpoint) with hashing to prevent key guessing and abuse.
- **Bypass Prevention**: Uses server-side timestamps and secure key generation to prevent clients from bypassing limits.
- **Distributed Consistency**: Leverages Redis for distributed rate limiting, ensuring consistency across application instances.

## Resilience Features

To ensure reliability under failure conditions:
- **Graceful Degradation**: Falls back to in-memory rate limiting if Redis is unavailable.
- **Circuit Breaker**: Prevents repeated failed attempts to connect to Redis, reducing system strain.
- **TTL-based Cleanup**: Automatically expires old rate limit data in Redis to prevent memory bloat.

## Observability

The system provides comprehensive observability:
- **Metrics Collection**: Tracks allowed/denied requests, remaining quotas, and latency.
- **Distributed Tracing**: Integrates with tracing tools to monitor rate limit decision paths.
- **Logging**: Detailed logs for rate limit events, useful for debugging and audit trails.

## Testing

The rate limiting system is thoroughly tested with a comprehensive test suite in `tests/unit/core/test_advanced_rate_limiter.py`, following **Test-Driven Development (TDD)** principles:

### Test Categories
1. **Value Objects**: Validates key creation, uniqueness, and quota calculations.
2. **Algorithms**: Tests precision and accuracy of Token Bucket, Sliding Window, and Fixed Window algorithms.
3. **Policy Service**: Verifies hierarchical policy resolution and caching behavior.
4. **Core Functionality**: Ensures correct enforcement of limits and concurrent request handling.
5. **Resilience**: Tests graceful degradation under Redis failures and circuit breaker behavior.
6. **Observability**: Confirms metrics collection and tracing integration.
7. **Performance**: Validates sub-millisecond latency and bounded memory usage under load.
8. **Security**: Tests anti-abuse key generation and bypass prevention mechanisms.

### Test Coverage
- Over 90% coverage for critical rate limiting components.
- Includes edge cases, boundary conditions, and failure modes.
- Uses mocking to isolate dependencies and ensure repeatable tests.

### Running Tests
To run the rate limiting tests:
```bash
pytest tests/unit/core/test_advanced_rate_limiter.py -v
```

## Performance Considerations

The system is optimized for high performance:
- **Sub-Millisecond Latency**: Designed to add minimal overhead to request processing.
- **Memory Efficiency**: Uses compact data structures and TTLs to bound memory usage.
- **Concurrent Request Handling**: Safely handles high concurrency with atomic Redis operations.

Performance benchmarks are included in the test suite to ensure these requirements are met under load.

## Extending the System

### Adding New Algorithms
To add a new rate limiting algorithm:
1. Implement the algorithm logic in `RateLimitService` or a dedicated class.
2. Update the algorithm selection logic in `check_rate_limit` method.
3. Add corresponding tests to validate the new algorithm's behavior.

Example skeleton for a new algorithm:
```python
async def apply_new_algorithm(self, quota: RateLimitQuota, key: RateLimitKey, timestamp: float) -> RateLimitResult:
    # Implement new algorithm logic here
    pass
```

### Custom Policies
Define custom policies by extending `RateLimitPolicy` with new scope criteria or dynamic quota adjustments based on runtime conditions.

### Alternative Storage Backends
Implement a new repository by subclassing `RateLimitRepository` to support alternative storage systems (e.g., Memcached, in-memory for testing).

## Troubleshooting

### Common Issues
- **Rate Limit Not Applied**: Check if `RATE_LIMIT_ENABLED` is set to `True` and ensure Redis is accessible.
- **Unexpected Denials**: Verify policy configurations and hierarchical priorities. Check server time synchronization for distributed setups.
- **Performance Issues**: Monitor Redis latency and ensure sufficient memory and CPU resources.

### Debugging Tips
- Enable detailed logging to trace rate limit decisions.
- Use metrics to identify bottlenecks or misconfigured quotas.
- Review Redis key patterns to ensure correct key generation and expiration.

## Conclusion

The Advanced Rate Limiting System in `cedrina` is a robust, scalable, and secure solution for controlling request rates across API endpoints. Built with DDD principles, it provides a clean separation of concerns, comprehensive test coverage, and production-ready features like resilience, observability, and performance optimization. Whether protecting against abuse, ensuring fair usage, or maintaining system stability, this system offers the flexibility and reliability needed for modern web applications.

For further questions or contributions, please refer to the project's contribution guidelines or contact the development team. 