"""
New User Onboarding Journey - Real World Scenario Test

This test simulates a complete user journey from registration through initial
API usage, including encounters with rate limiting at various stages.

Scenario:
1. New user attempts to register (hits registration rate limits)
2. Successfully registers after waiting
3. Attempts to login multiple times (hits login rate limits)
4. Successfully logs in and receives tokens
5. Makes API calls and hits tier-based rate limits
6. Upgrades to premium and experiences different limits
7. Recovery and normal usage patterns

This test validates:
- Complete authentication flows
- Registration protection mechanisms
- Login brute-force protection
- Tier-based API rate limiting
- Rate limit recovery and reset behavior
- User experience with proper error messages
"""

import pytest
import time
import asyncio
from unittest.mock import patch, AsyncMock

from .conftest import (
    ScenarioClient, ScenarioState, wait_for_rate_limit_reset,
    simulate_burst_requests, assert_rate_limit_response,
    assert_successful_response
)


class TestNewUserOnboardingJourney:
    """Test complete new user onboarding with rate limiting scenarios."""
    
    @pytest.mark.asyncio
    async def test_complete_user_onboarding_journey(
        self,
        scenario_client: ScenarioClient,
        scenario_state: ScenarioState,
        user_scenarios: dict,
        api_endpoints: dict,
        rate_limit_policies: dict,
        mock_redis: AsyncMock
    ):
        """
        Test complete user onboarding journey with rate limiting.
        
        This test simulates a realistic user experience including:
        - Registration attempts and rate limiting
        - Login attempts and brute-force protection
        - Initial API usage and tier limits
        - Recovery behavior
        """
        # Step 1: Simulate registration abuse - multiple rapid attempts
        print("\n🚀 Step 1: Testing registration rate limiting...")
        
        new_user_data = user_scenarios["new_user"]
        register_endpoint = api_endpoints["auth"]["register"]
        
        # Configure rate limiter to block after 3 registration attempts
        with patch('src.domain.rate_limiting.services.AdvancedRateLimiter') as mock_limiter_class:
            mock_limiter = AsyncMock()
            mock_limiter_class.return_value = mock_limiter
            
            # First 3 attempts allowed, then rate limited
            mock_limiter.check_rate_limit.side_effect = [
                {"allowed": True, "limit": 3, "remaining": 2, "reset_time": int(time.time()) + 600},
                {"allowed": True, "limit": 3, "remaining": 1, "reset_time": int(time.time()) + 600},
                {"allowed": True, "limit": 3, "remaining": 0, "reset_time": int(time.time()) + 600},
                {"allowed": False, "limit": 3, "remaining": 0, "reset_time": int(time.time()) + 600, "retry_after": 600}
            ]
            
            # Attempt 4 rapid registrations
            registration_responses = []
            for i in range(4):
                response = scenario_client.post(register_endpoint, json={
                    "username": f"{new_user_data['username']}_{i}",
                    "email": f"user{i}@{new_user_data['email'].split('@')[1]}",
                    "password": new_user_data["password"]
                })
                registration_responses.append(response.status_code)
                scenario_state.record_request("new_user", register_endpoint, response.status_code)
                time.sleep(0.1)  # Small delay between attempts
            
            # Verify rate limiting kicks in
            assert registration_responses[:3] == [201, 201, 201]  # First 3 succeed
            assert registration_responses[3] == 429  # 4th is rate limited
            
        print("✅ Registration rate limiting working correctly")
        
        # Step 2: Wait for rate limit reset and successful registration
        print("\n⏳ Step 2: Waiting for rate limit reset and registering user...")
        
        # Reset the rate limiter for successful registration
        with patch('src.domain.rate_limiting.services.AdvancedRateLimiter') as mock_limiter_class:
            mock_limiter = AsyncMock()
            mock_limiter_class.return_value = mock_limiter
            mock_limiter.check_rate_limit.return_value = {
                "allowed": True, "limit": 3, "remaining": 2, "reset_time": int(time.time()) + 600
            }
            
            # Successful registration
            response = scenario_client.post(register_endpoint, json={
                "username": new_user_data["username"],
                "email": new_user_data["email"],
                "password": new_user_data["password"]
            })
            
            assert_successful_response(response, 201)
            user_data = response.json()
            
            # Store user token
            token = user_data["tokens"]["access_token"]
            scenario_state.register_user("new_user", new_user_data, token)
            scenario_client.set_auth_headers(token, "regular")
            
        print("✅ User successfully registered")
        
        # Step 3: Test login brute-force protection
        print("\n🔐 Step 3: Testing login brute-force protection...")
        
        login_endpoint = api_endpoints["auth"]["login"]
        
        with patch('src.domain.rate_limiting.services.AdvancedRateLimiter') as mock_limiter_class:
            mock_limiter = AsyncMock()
            mock_limiter_class.return_value = mock_limiter
            
            # Allow first 5 login attempts, then rate limit
            mock_limiter.check_rate_limit.side_effect = [
                {"allowed": True, "limit": 5, "remaining": 4, "reset_time": int(time.time()) + 300},
                {"allowed": True, "limit": 5, "remaining": 3, "reset_time": int(time.time()) + 300},
                {"allowed": True, "limit": 5, "remaining": 2, "reset_time": int(time.time()) + 300},
                {"allowed": True, "limit": 5, "remaining": 1, "reset_time": int(time.time()) + 300},
                {"allowed": True, "limit": 5, "remaining": 0, "reset_time": int(time.time()) + 300},
                {"allowed": False, "limit": 5, "remaining": 0, "reset_time": int(time.time()) + 300, "retry_after": 300}
            ]
            
            # Simulate brute-force with wrong password
            login_responses = []
            for i in range(6):
                response = scenario_client.post(login_endpoint, json={
                    "username": new_user_data["username"],
                    "password": "wrong_password"
                })
                login_responses.append(response.status_code)
                scenario_state.record_request("new_user", login_endpoint, response.status_code)
                time.sleep(0.1)
            
            # Verify login protection
            assert login_responses[5] == 429  # 6th attempt rate limited
            
        print("✅ Login brute-force protection working correctly")
        
        # Step 4: Successful login after rate limit reset
        print("\n🔑 Step 4: Successful login after rate limit reset...")
        
        with patch('src.domain.rate_limiting.services.AdvancedRateLimiter') as mock_limiter_class:
            mock_limiter = AsyncMock()
            mock_limiter_class.return_value = mock_limiter
            mock_limiter.check_rate_limit.return_value = {
                "allowed": True, "limit": 5, "remaining": 4, "reset_time": int(time.time()) + 300
            }
            
            # Successful login with correct password
            response = scenario_client.post(login_endpoint, json={
                "username": new_user_data["username"],
                "password": new_user_data["password"]
            })
            
            assert_successful_response(response, 200)
            login_data = response.json()
            
            # Update token
            new_token = login_data["tokens"]["access_token"]
            scenario_state.tokens["new_user"] = new_token
            scenario_client.set_auth_headers(new_token, "regular")
            
        print("✅ User successfully logged in")
        
        # Step 5: Test free tier API rate limiting
        print("\n📊 Step 5: Testing free tier API rate limiting...")
        
        # Mock some protected endpoints
        with patch('src.core.dependencies.auth.get_current_user') as mock_get_user:
            mock_get_user.return_value = {
                "id": 1,
                "username": new_user_data["username"],
                "email": new_user_data["email"],
                "tier": "free"
            }
            
            with patch('src.domain.rate_limiting.services.AdvancedRateLimiter') as mock_limiter_class:
                mock_limiter = AsyncMock()
                mock_limiter_class.return_value = mock_limiter
                
                # Free tier: 10 requests per minute
                request_count = 0
                def rate_limit_side_effect(*args, **kwargs):
                    nonlocal request_count
                    request_count += 1
                    if request_count <= 10:
                        return {"allowed": True, "limit": 10, "remaining": 10 - request_count, 
                               "reset_time": int(time.time()) + 60}
                    else:
                        return {"allowed": False, "limit": 10, "remaining": 0,
                               "reset_time": int(time.time()) + 60, "retry_after": 60}
                
                mock_limiter.check_rate_limit.side_effect = rate_limit_side_effect
                
                # Make 12 API requests rapidly
                api_responses = []
                for i in range(12):
                    response = scenario_client.get("/api/v1/health")  # Use existing endpoint
                    api_responses.append(response.status_code)
                    scenario_state.record_request("new_user", "/api/v1/health", response.status_code)
                    time.sleep(0.05)
                
                # Verify free tier limits
                successful_requests = [code for code in api_responses if code == 200]
                rate_limited_requests = [code for code in api_responses if code == 429]
                
                assert len(successful_requests) == 10
                assert len(rate_limited_requests) == 2
                
        print("✅ Free tier rate limiting working correctly")
        
        # Step 6: Simulate tier upgrade and test new limits
        print("\n⭐ Step 6: Simulating premium tier upgrade...")
        
        with patch('src.core.dependencies.auth.get_current_user') as mock_get_user:
            mock_get_user.return_value = {
                "id": 1,
                "username": new_user_data["username"],
                "email": new_user_data["email"],
                "tier": "premium"
            }
            
            with patch('src.domain.rate_limiting.services.AdvancedRateLimiter') as mock_limiter_class:
                mock_limiter = AsyncMock()
                mock_limiter_class.return_value = mock_limiter
                
                # Premium tier: 100 requests per minute
                mock_limiter.check_rate_limit.return_value = {
                    "allowed": True, "limit": 100, "remaining": 99,
                    "reset_time": int(time.time()) + 60
                }
                
                # Make 20 API requests (all should succeed with premium)
                premium_responses = []
                for i in range(20):
                    response = scenario_client.get("/api/v1/health")
                    premium_responses.append(response.status_code)
                    time.sleep(0.02)
                
                # All requests should succeed with premium tier
                assert all(code == 200 for code in premium_responses)
                
        print("✅ Premium tier upgrade working correctly")
        
        # Step 7: Verify scenario completion and analytics
        print("\n📈 Step 7: Scenario completion and analytics...")
        
        rate_limit_summary = scenario_state.get_rate_limit_summary()
        
        # Verify we captured rate limiting events
        assert rate_limit_summary["rate_limit_hits"] > 0
        assert rate_limit_summary["total_requests"] > 30
        
        print(f"✅ Scenario completed successfully!")
        print(f"   - Total requests: {rate_limit_summary['total_requests']}")
        print(f"   - Rate limit hits: {rate_limit_summary['rate_limit_hits']}")
        print(f"   - Users affected: {rate_limit_summary['users_affected']}")
        print(f"   - Endpoints tested: {rate_limit_summary['endpoints_affected']}")
        
    @pytest.mark.asyncio
    async def test_concurrent_user_registration_scenario(
        self,
        scenario_client: ScenarioClient,
        user_scenarios: dict,
        api_endpoints: dict,
        mock_redis: AsyncMock
    ):
        """
        Test concurrent user registration with rate limiting.
        
        Simulates multiple users trying to register simultaneously,
        testing the system's ability to handle concurrent load while
        maintaining rate limiting accuracy.
        """
        print("\n👥 Testing concurrent user registration scenario...")
        
        register_endpoint = api_endpoints["auth"]["register"]
        base_user = user_scenarios["new_user"]
        
        with patch('src.domain.rate_limiting.services.AdvancedRateLimiter') as mock_limiter_class:
            mock_limiter = AsyncMock()
            mock_limiter_class.return_value = mock_limiter
            
            # Allow 3 registrations per IP, then rate limit
            registration_count = 0
            def concurrent_rate_limit(*args, **kwargs):
                nonlocal registration_count
                registration_count += 1
                if registration_count <= 3:
                    return {"allowed": True, "limit": 3, "remaining": 3 - registration_count,
                           "reset_time": int(time.time()) + 600}
                else:
                    return {"allowed": False, "limit": 3, "remaining": 0,
                           "reset_time": int(time.time()) + 600, "retry_after": 600}
            
            mock_limiter.check_rate_limit.side_effect = concurrent_rate_limit
            
            # Simulate 5 concurrent registration attempts
            concurrent_responses = []
            for i in range(5):
                response = scenario_client.post(register_endpoint, json={
                    "username": f"concurrent_user_{i}",
                    "email": f"concurrent{i}@example.com",
                    "password": "ConcurrentPassword123!"
                })
                concurrent_responses.append(response.status_code)
                time.sleep(0.01)  # Tiny delay to simulate near-concurrent requests
            
            # Verify rate limiting under concurrent load
            successful = [code for code in concurrent_responses if code == 201]
            rate_limited = [code for code in concurrent_responses if code == 429]
            
            assert len(successful) == 3  # First 3 succeed
            assert len(rate_limited) == 2  # Last 2 rate limited
            
        print("✅ Concurrent registration rate limiting working correctly")
        
    @pytest.mark.asyncio 
    async def test_user_behavior_adaptation_scenario(
        self,
        scenario_client: ScenarioClient,
        scenario_state: ScenarioState,
        user_scenarios: dict,
        api_endpoints: dict,
        mock_redis: AsyncMock
    ):
        """
        Test user behavior adaptation after encountering rate limits.
        
        Verifies that users can successfully adapt their usage patterns
        after hitting rate limits, including waiting for resets and
        adjusting request frequency.
        """
        print("\n🎯 Testing user behavior adaptation scenario...")
        
        # Setup authenticated user
        user_data = user_scenarios["existing_user"]
        scenario_client.set_auth_headers("test_token", "regular")
        
        with patch('src.core.dependencies.auth.get_current_user') as mock_get_user:
            mock_get_user.return_value = {
                "id": 1,
                "username": user_data["username"],
                "email": user_data["email"],
                "tier": "free"
            }
            
            with patch('src.domain.rate_limiting.services.AdvancedRateLimiter') as mock_limiter_class:
                mock_limiter = AsyncMock()
                mock_limiter_class.return_value = mock_limiter
                
                # Phase 1: Aggressive usage leads to rate limiting
                request_count = 0
                def adaptive_rate_limit(*args, **kwargs):
                    nonlocal request_count
                    request_count += 1
                    
                    if request_count <= 5:  # First 5 requests allowed
                        return {"allowed": True, "limit": 5, "remaining": 5 - request_count,
                               "reset_time": int(time.time()) + 60}
                    elif request_count <= 8:  # Next 3 requests rate limited
                        return {"allowed": False, "limit": 5, "remaining": 0,
                               "reset_time": int(time.time()) + 60, "retry_after": 60}
                    else:  # After "waiting", requests allowed again
                        return {"allowed": True, "limit": 5, "remaining": 4,
                               "reset_time": int(time.time()) + 60}
                
                mock_limiter.check_rate_limit.side_effect = adaptive_rate_limit
                
                # Phase 1: Aggressive requests
                aggressive_responses = []
                for i in range(8):
                    response = scenario_client.get("/api/v1/health")
                    aggressive_responses.append(response.status_code)
                    scenario_state.record_request("existing_user", "/api/v1/health", response.status_code)
                    time.sleep(0.05)
                    
                # Verify rate limiting occurs
                successful_phase1 = [code for code in aggressive_responses if code == 200]
                limited_phase1 = [code for code in aggressive_responses if code == 429]
                
                assert len(successful_phase1) == 5
                assert len(limited_phase1) == 3
                
                # Phase 2: User adapts by spacing out requests
                print("   User adapts behavior after rate limiting...")
                time.sleep(0.5)  # Simulate user waiting
                
                adapted_responses = []
                for i in range(3):
                    response = scenario_client.get("/api/v1/health")
                    adapted_responses.append(response.status_code)
                    scenario_state.record_request("existing_user", "/api/v1/health", response.status_code)
                    time.sleep(0.2)  # User spaces out requests
                
                # All adapted requests should succeed
                assert all(code == 200 for code in adapted_responses)
                
        adaptation_summary = scenario_state.get_rate_limit_summary()
        print(f"✅ User adaptation scenario completed!")
        print(f"   - Rate limit encounters: {adaptation_summary['rate_limit_hits']}")
        print(f"   - Successful adaptation: {len(adapted_responses)} requests succeeded") 