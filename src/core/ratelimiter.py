from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request
from src.core.config.settings import settings

# A set of targeted authentication routes for rate-limiting.
# Using a set provides efficient 'in' checks.
AUTH_ROUTES = {
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/oauth",
}

# Public routes that should not be rate-limited by this function.
PUBLIC_ROUTES = {
    "/api/v1/health",
    "/api/v1/health/"
}


def default_key_func(request: Request) -> str:
    """
    Constructs a rate limit key based on client IP and username (if provided in the request).
    
    Args:
        request: The incoming HTTP request.
    
    Returns:
        A string representing the rate limit key.
    """
    # Get client IP
    client_host = request.client.host if request.client else 'unknown'
    
    # Try to extract username from request body (for POST requests)
    username = 'anonymous'
    if request.method == 'POST':
        try:
            # Access the body only if it's a JSON request
            content_type = request.headers.get('content-type', '')
            if 'application/json' in content_type:
                body = request._json
                if isinstance(body, dict):
                    username = body.get('username', 'anonymous')
        except Exception:
            pass
    
    return f"{client_host}:{username}"

def key_func(request: Request) -> str | None:
    """
    Determines the rate-limiting key for a given request.

    This function applies rate-limiting based on the client's IP address, but only
    for requests made to designated authentication endpoints. Other routes are not
    limited by this function.

    Security Note:
        For the login endpoint, a more secure keying strategy would combine the
        username with the IP address (e.g., "username:ip_address"). This approach
        prevents a single user from attempting to brute-force multiple accounts
        from one IP, and vice-versa. Implementing this requires accessing the
        request body, which is complex to do safely within a middleware without
        disrupting FastAPI's processing. The current IP-based approach provides a
        strong baseline defense against simple, large-scale attacks.

    Args:
        request (Request): The incoming Starlette request object.

    Returns:
        Optional[str]: The client's remote address if the route is targeted
                       for rate-limiting, otherwise None.
    """
    if request.url.path in PUBLIC_ROUTES:
        return None  # Do not rate-limit public routes
    if request.url.path in AUTH_ROUTES:
        return get_remote_address(request)
    return None

# Removed async key_func and sync wrapper due to event loop issues

def get_limiter() -> Limiter:
    """
    Factory function for the rate limiter.
    
    This function creates and returns a Limiter instance based on the application
    settings. This factory pattern allows for late initialization, making it
    compatible with testing environments where settings might be monkey-patched.
    
    Returns:
        Limiter: A configured slowapi.Limiter instance.
    """
    return Limiter(
        key_func=key_func,
        enabled=settings.RATE_LIMIT_ENABLED,
        default_limits=[settings.RATE_LIMIT_AUTH],
        storage_uri=settings.RATE_LIMIT_STORAGE_URL,
        strategy=settings.RATE_LIMIT_STRATEGY,
    ) 