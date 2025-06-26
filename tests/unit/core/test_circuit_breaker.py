import asyncio
import pytest
import sys
import os

from unittest.mock import AsyncMock, patch
from datetime import datetime, timedelta

# Adjust sys.path to include src directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../src')))

from core.circuit_breaker import CircuitBreaker, circuit_breaker


@pytest.mark.asyncio
async def test_circuit_breaker_initial_state():
    """Test that the circuit breaker starts in closed state."""
    breaker = CircuitBreaker(failure_threshold=3, reset_timeout=10, half_open_timeout=5, name="test")
    assert breaker.state == "closed"
    assert breaker.failures == 0


@pytest.mark.asyncio
async def test_circuit_breaker_closed_to_open():
    """Test transition from closed to open state after failure threshold is reached."""
    breaker = CircuitBreaker(failure_threshold=3, reset_timeout=10, half_open_timeout=5, name="test")
    
    # Simulate failures
    for _ in range(3):
        await breaker._update_state(False)
    
    assert breaker.state == "open"
    assert breaker.failures == 3
    assert breaker.last_failure_time is not None


@pytest.mark.asyncio
async def test_circuit_breaker_open_to_half_open():
    """Test transition from open to half-open state after reset timeout."""
    breaker = CircuitBreaker(failure_threshold=3, reset_timeout=1, half_open_timeout=5, name="test")
    
    # Simulate failures to open state
    for _ in range(3):
        await breaker._update_state(False)
    
    assert breaker.state == "open"
    
    # Wait for reset timeout
    await asyncio.sleep(1.1)
    can_execute = await breaker._check_state()
    assert breaker.state == "half-open"
    assert can_execute is True


@pytest.mark.asyncio
async def test_circuit_breaker_half_open_to_closed():
    """Test transition from half-open to closed state after successful execution."""
    breaker = CircuitBreaker(failure_threshold=3, reset_timeout=1, half_open_timeout=5, name="test")
    
    # Simulate failures to open state
    for _ in range(3):
        await breaker._update_state(False)
    
    # Wait for reset timeout to move to half-open
    await asyncio.sleep(1.1)
    await breaker._check_state()
    assert breaker.state == "half-open"
    
    # Simulate success
    await breaker._update_state(True)
    assert breaker.state == "closed"
    assert breaker.failures == 0


@pytest.mark.asyncio
async def test_circuit_breaker_execute_success():
    """Test successful execution through circuit breaker."""
    breaker = CircuitBreaker(failure_threshold=3, reset_timeout=10, half_open_timeout=5, name="test")
    mock_func = AsyncMock(return_value="success")
    
    result = await breaker.execute(mock_func)
    assert result == "success"
    assert breaker.state == "closed"
    assert breaker.failures == 0


@pytest.mark.asyncio
async def test_circuit_breaker_execute_failure_open():
    """Test circuit breaker blocks execution when open."""
    breaker = CircuitBreaker(failure_threshold=3, reset_timeout=10, half_open_timeout=5, name="test")
    
    # Simulate failures to open state
    for _ in range(3):
        await breaker._update_state(False)
    
    mock_func = AsyncMock(return_value="success")
    with pytest.raises(Exception, match="Circuit breaker test is open"):
        await breaker.execute(mock_func)


@pytest.mark.asyncio
async def test_circuit_breaker_decorator_success():
    """Test circuit breaker decorator with successful async function."""
    @circuit_breaker(failure_threshold=3, reset_timeout=10, half_open_timeout=5, name="decorated")
    async def test_func():
        return "success"
    
    result = await test_func()
    assert result == "success"


@pytest.mark.asyncio
async def test_circuit_breaker_decorator_failure():
    """Test circuit breaker decorator with failing async function."""
    @circuit_breaker(failure_threshold=1, reset_timeout=10, half_open_timeout=5, name="decorated_fail")
    async def test_func():
        raise ValueError("fail")
    
    with pytest.raises(ValueError, match="fail"):
        await test_func() 