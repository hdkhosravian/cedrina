"""Unit tests for rate limiting disable functionality.

Tests the ability to disable rate limiting at various levels:
- Global disable
- IP-based disable
- User-based disable
- Endpoint-based disable
- Tier-based disable
- Emergency disable
"""

from src.core.rate_limiting.config import RateLimitingConfig


class TestRateLimitingConfigDisable:
    """Test rate limiting configuration disable functionality."""

    def test_global_disable_via_disable_rate_limiting(self):
        """Test global disable via disable_rate_limiting flag."""
        config = RateLimitingConfig(enable_rate_limiting=True, disable_rate_limiting=True)

        assert config.is_rate_limiting_disabled() is True
        assert config.should_bypass_rate_limit() is True
        assert (
            config.get_bypass_reason()
            == "Rate limiting globally disabled via RATE_LIMITING_DISABLED"
        )

    def test_global_disable_via_emergency_disable(self):
        """Test global disable via emergency_disable flag."""
        config = RateLimitingConfig(enable_rate_limiting=True, emergency_disable=True)

        assert config.is_rate_limiting_disabled() is True
        assert config.should_bypass_rate_limit() is True
        assert (
            config.get_bypass_reason()
            == "Rate limiting disabled via emergency override (RATE_LIMITING_EMERGENCY_DISABLE)"
        )

    def test_global_disable_via_enable_rate_limiting_false(self):
        """Test global disable via enable_rate_limiting=False."""
        config = RateLimitingConfig(enable_rate_limiting=False)

        assert config.is_rate_limiting_disabled() is True
        assert config.should_bypass_rate_limit() is True
        assert (
            config.get_bypass_reason()
            == "Rate limiting globally disabled via RATE_LIMITING_ENABLED=false"
        )

    def test_ip_based_bypass(self):
        """Test IP-based rate limiting bypass."""
        config = RateLimitingConfig(
            enable_rate_limiting=True, disable_for_ips={"192.168.1.1", "10.0.0.1"}
        )

        # Should bypass for configured IPs
        assert config.should_bypass_rate_limit(client_ip="192.168.1.1") is True
        assert config.should_bypass_rate_limit(client_ip="10.0.0.1") is True
        assert (
            config.get_bypass_reason(client_ip="192.168.1.1")
            == "Rate limiting disabled for IP: 192.168.1.1"
        )

        # Should not bypass for other IPs
        assert config.should_bypass_rate_limit(client_ip="192.168.1.2") is False
        assert config.get_bypass_reason(client_ip="192.168.1.2") is None

    def test_user_based_bypass(self):
        """Test user-based rate limiting bypass."""
        config = RateLimitingConfig(
            enable_rate_limiting=True, disable_for_users={"admin", "test_user"}
        )

        # Should bypass for configured users
        assert config.should_bypass_rate_limit(user_id="admin") is True
        assert config.should_bypass_rate_limit(user_id="test_user") is True
        assert config.get_bypass_reason(user_id="admin") == "Rate limiting disabled for user: admin"

        # Should not bypass for other users
        assert config.should_bypass_rate_limit(user_id="regular_user") is False
        assert config.get_bypass_reason(user_id="regular_user") is None

    def test_endpoint_based_bypass(self):
        """Test endpoint-based rate limiting bypass."""
        config = RateLimitingConfig(
            enable_rate_limiting=True, disable_for_endpoints={"/api/v1/health", "/api/v1/metrics"}
        )

        # Should bypass for configured endpoints
        assert config.should_bypass_rate_limit(endpoint="/api/v1/health") is True
        assert config.should_bypass_rate_limit(endpoint="/api/v1/metrics") is True
        assert (
            config.get_bypass_reason(endpoint="/api/v1/health")
            == "Rate limiting disabled for endpoint: /api/v1/health"
        )

        # Should not bypass for other endpoints
        assert config.should_bypass_rate_limit(endpoint="/api/v1/auth/login") is False
        assert config.get_bypass_reason(endpoint="/api/v1/auth/login") is None

    def test_tier_based_bypass(self):
        """Test tier-based rate limiting bypass."""
        config = RateLimitingConfig(
            enable_rate_limiting=True, disable_for_user_tiers={"premium", "enterprise"}
        )

        # Should bypass for configured tiers
        assert config.should_bypass_rate_limit(user_tier="premium") is True
        assert config.should_bypass_rate_limit(user_tier="enterprise") is True
        assert (
            config.get_bypass_reason(user_tier="premium")
            == "Rate limiting disabled for tier: premium"
        )

        # Should not bypass for other tiers
        assert config.should_bypass_rate_limit(user_tier="free") is False
        assert config.get_bypass_reason(user_tier="free") is None

    def test_multiple_bypass_conditions(self):
        """Test multiple bypass conditions together."""
        config = RateLimitingConfig(
            enable_rate_limiting=True,
            disable_for_ips={"192.168.1.1"},
            disable_for_users={"admin"},
            disable_for_endpoints={"/api/v1/health"},
            disable_for_user_tiers={"premium"},
        )

        # Should bypass when any condition is met
        assert config.should_bypass_rate_limit(client_ip="192.168.1.1") is True
        assert config.should_bypass_rate_limit(user_id="admin") is True
        assert config.should_bypass_rate_limit(endpoint="/api/v1/health") is True
        assert config.should_bypass_rate_limit(user_tier="premium") is True

        # Should not bypass when no conditions are met
        assert (
            config.should_bypass_rate_limit(
                client_ip="192.168.1.2",
                user_id="user1",
                endpoint="/api/v1/auth/login",
                user_tier="free",
            )
            is False
        )

    def test_comma_separated_parsing(self):
        """Test parsing comma-separated values for bypass lists."""
        config = RateLimitingConfig(
            enable_rate_limiting=True,
            disable_for_ips="192.168.1.1,10.0.0.1",
            disable_for_users="admin,test_user",
            disable_for_endpoints="/api/v1/health,/api/v1/metrics",
            disable_for_user_tiers="premium,enterprise",
        )

        assert config.disable_for_ips == {"192.168.1.1", "10.0.0.1"}
        assert config.disable_for_users == {"admin", "test_user"}
        assert config.disable_for_endpoints == {"/api/v1/health", "/api/v1/metrics"}
        assert config.disable_for_user_tiers == {"premium", "enterprise"}

    def test_empty_policies_when_disabled(self):
        """Test that no policies are created when rate limiting is disabled."""
        config = RateLimitingConfig(enable_rate_limiting=True, disable_rate_limiting=True)

        policies = config.create_policies()
        assert policies == []
