from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, AsyncMock

import pytest

from src.core.exceptions import AuthenticationError, SessionLimitExceededError
from src.domain.entities.session import Session
from src.domain.services.auth.session import SessionService
from src.utils.i18n import get_translated_message, setup_i18n


@pytest.fixture(scope="session", autouse=True)
def setup_i18n_for_tests():
    """Setup i18n system for all tests."""
    setup_i18n()


@pytest.fixture
def session_service(db_session, redis_client):
    """Provides a SessionService instance with mocked dependencies."""
    return SessionService(db_session, redis_client)


@pytest.mark.asyncio
async def test_create_session(session_service, db_session, redis_client):
    # Arrange
    user_id = 1
    jti = "test_jti"
    refresh_token_hash = "some_hash"
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    
    # Mock session limit check
    session_service._enforce_session_limits = AsyncMock()
    session_service._get_active_session_count = AsyncMock(return_value=1)
    
    # Mock Redis and DB operations
    redis_client.setex = AsyncMock()
    db_session.add = MagicMock()
    db_session.commit = AsyncMock()
    db_session.refresh = AsyncMock()

    # Act
    session = await session_service.create_session(user_id, jti, refresh_token_hash, expires_at)

    # Assert
    assert session.user_id == user_id
    assert session.jti == jti
    assert session.refresh_token_hash == refresh_token_hash
    assert session.last_activity_at is not None
    session_service._enforce_session_limits.assert_called_once_with(user_id)
    db_session.add.assert_called_once()
    db_session.commit.assert_called_once()
    db_session.refresh.assert_called_once_with(session)


@pytest.mark.asyncio
async def test_create_session_with_consistency_timeout(session_service, db_session, redis_client):
    # Arrange
    user_id = 1
    jti = "test_jti"
    refresh_token_hash = "some_hash"
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    
    # Mock session limit check
    session_service._enforce_session_limits = AsyncMock()
    
    # Mock Redis to timeout
    redis_client.setex = AsyncMock(side_effect=Exception("Redis timeout"))
    db_session.add = MagicMock()
    db_session.commit = AsyncMock()
    
    # Mock cleanup
    session_service._cleanup_failed_session_creation = AsyncMock()

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Session creation failed due to an internal error"):
        await session_service.create_session(user_id, jti, refresh_token_hash, expires_at)
    
    session_service._cleanup_failed_session_creation.assert_called_once_with(jti, user_id)


@pytest.mark.asyncio
async def test_update_session_activity_success(session_service, db_session, redis_client):
    # Arrange
    user_id = 1
    jti = "test-jti"
    current_time = datetime.now(timezone.utc)
    session = Session(
        user_id=user_id,
        jti=jti,
        refresh_token_hash="hashed_token",
        expires_at=current_time + timedelta(days=1),
        last_activity_at=current_time - timedelta(minutes=10),
    )
    
    db_session.exec.return_value.first = MagicMock(return_value=session)
    db_session.add = MagicMock()
    db_session.commit = AsyncMock()
    redis_client.hset = AsyncMock()

    # Act
    result = await session_service.update_session_activity(jti, user_id)

    # Assert
    assert result is True
    assert session.last_activity_at > current_time - timedelta(minutes=10)
    db_session.add.assert_called_once_with(session)
    db_session.commit.assert_called_once()
    redis_client.hset.assert_called_once()


@pytest.mark.asyncio
async def test_update_session_activity_expired(session_service, db_session):
    # Arrange
    user_id = 1
    jti = "test-jti"
    current_time = datetime.now(timezone.utc)
    session = Session(
        user_id=user_id,
        jti=jti,
        refresh_token_hash="hashed_token",
        expires_at=current_time - timedelta(days=1),  # Expired
        last_activity_at=current_time - timedelta(minutes=10),
    )
    
    db_session.exec.return_value.first = MagicMock(return_value=session)

    # Act
    result = await session_service.update_session_activity(jti, user_id)

    # Assert
    assert result is False


@pytest.mark.asyncio
async def test_update_session_activity_inactivity_timeout(session_service, db_session, redis_client):
    # Arrange
    user_id = 1
    jti = "test-jti"
    current_time = datetime.now(timezone.utc)
    session = Session(
        user_id=user_id,
        jti=jti,
        refresh_token_hash="hashed_token",
        expires_at=current_time + timedelta(days=1),
        last_activity_at=current_time - timedelta(hours=1),  # Inactive for 1 hour
    )
    
    db_session.exec.return_value.first = MagicMock(return_value=session)
    session_service.revoke_session = AsyncMock()

    # Act
    result = await session_service.update_session_activity(jti, user_id)

    # Assert
    assert result is False
    session_service.revoke_session.assert_called_once_with(jti, user_id, "en")


@pytest.mark.asyncio
async def test_revoke_session_success(session_service, db_session, redis_client):
    # Arrange
    user_id = 1
    jti = "test-jti"
    session = Session(user_id=user_id, jti=jti, refresh_token_hash="hashed_token")
    db_session.exec.return_value.first = MagicMock(return_value=session)
    
    # Mock Redis operations
    redis_client.delete = AsyncMock()
    redis_client.setex = AsyncMock()
    
    db_session.add = MagicMock()
    db_session.commit = AsyncMock()

    # Act
    await session_service.revoke_session(jti, user_id, "en")

    # Assert
    assert session.revoked_at is not None
    db_session.add.assert_called_once_with(session)
    db_session.commit.assert_called_once()
    redis_client.delete.assert_called()
    redis_client.setex.assert_called_once()  # For access token blacklisting


@pytest.mark.asyncio
async def test_revoke_session_not_found(session_service, db_session):
    # Arrange
    db_session.exec.return_value.first = MagicMock(return_value=None)

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Session revoked or invalid"):
        await session_service.revoke_session("non_existent_jti", 1, "en")


@pytest.mark.asyncio
async def test_is_session_valid_valid(session_service, db_session, redis_client):
    # Arrange
    user_id = 1
    jti = "test-jti"
    current_time = datetime.now(timezone.utc)
    session = Session(
        user_id=user_id,
        jti=jti,
        refresh_token_hash="hashed_token",
        expires_at=current_time + timedelta(days=1),
        last_activity_at=current_time - timedelta(minutes=10),
    )
    db_session.exec.return_value.first = MagicMock(return_value=session)
    redis_client.get = AsyncMock(return_value=b"some_hash")

    # Act
    is_valid = await session_service.is_session_valid(jti, user_id)

    # Assert
    assert is_valid is True


@pytest.mark.asyncio
async def test_is_session_valid_expired(session_service, db_session):
    # Arrange
    user_id = 1
    jti = "test-jti"
    current_time = datetime.now(timezone.utc)
    session = Session(
        user_id=user_id,
        jti=jti,
        refresh_token_hash="hashed_token",
        expires_at=current_time - timedelta(days=1),  # Expired
        last_activity_at=current_time - timedelta(minutes=10),
    )
    db_session.exec.return_value.first = MagicMock(return_value=session)

    # Act
    is_valid = await session_service.is_session_valid(jti, user_id)

    # Assert
    assert is_valid is False


@pytest.mark.asyncio
async def test_is_session_valid_inactivity_timeout(session_service, db_session):
    # Arrange
    user_id = 1
    jti = "test-jti"
    current_time = datetime.now(timezone.utc)
    session = Session(
        user_id=user_id,
        jti=jti,
        refresh_token_hash="hashed_token",
        expires_at=current_time + timedelta(days=1),
        last_activity_at=current_time - timedelta(hours=1),  # Inactive for 1 hour
    )
    db_session.exec.return_value.first = MagicMock(return_value=session)

    # Act
    is_valid = await session_service.is_session_valid(jti, user_id)

    # Assert
    assert is_valid is False


@pytest.mark.asyncio
async def test_is_session_valid_redis_inconsistency(session_service, db_session, redis_client):
    # Arrange
    user_id = 1
    jti = "test-jti"
    current_time = datetime.now(timezone.utc)
    session = Session(
        user_id=user_id,
        jti=jti,
        refresh_token_hash="hashed_token",
        expires_at=current_time + timedelta(days=1),
        last_activity_at=current_time - timedelta(minutes=10),
    )
    db_session.exec.return_value.first = MagicMock(return_value=session)
    redis_client.get = AsyncMock(return_value=None)  # Redis inconsistency

    # Act
    is_valid = await session_service.is_session_valid(jti, user_id)

    # Assert
    assert is_valid is False


@pytest.mark.asyncio
async def test_get_user_active_sessions(session_service, db_session):
    # Arrange
    user_id = 1
    current_time = datetime.now(timezone.utc)
    active_session = Session(
        user_id=user_id,
        jti="active_jti",
        refresh_token_hash="hash1",
        expires_at=current_time + timedelta(days=1),
        last_activity_at=current_time - timedelta(minutes=10),
    )
    expired_session = Session(
        user_id=user_id,
        jti="expired_jti",
        refresh_token_hash="hash2",
        expires_at=current_time - timedelta(days=1),
        last_activity_at=current_time - timedelta(minutes=10),
    )
    
    db_session.exec.return_value.all = MagicMock(return_value=[active_session])

    # Act
    sessions = await session_service.get_user_active_sessions(user_id)

    # Assert
    assert len(sessions) == 1
    assert sessions[0].jti == "active_jti"


@pytest.mark.asyncio
async def test_cleanup_expired_sessions(session_service, db_session, redis_client):
    # Arrange
    current_time = datetime.now(timezone.utc)
    expired_session = Session(
        user_id=1,
        jti="expired_jti",
        refresh_token_hash="hash",
        expires_at=current_time - timedelta(days=1),
        last_activity_at=current_time - timedelta(hours=1),
    )
    
    db_session.exec.return_value.all = MagicMock(return_value=[expired_session])
    db_session.delete = AsyncMock()
    db_session.commit = AsyncMock()
    redis_client.delete = AsyncMock()

    # Act
    count = await session_service.cleanup_expired_sessions()

    # Assert
    assert count == 1
    db_session.delete.assert_called_once_with(expired_session)
    db_session.commit.assert_called_once()
    redis_client.delete.assert_called_once()


@pytest.mark.asyncio
async def test_enforce_session_limits(session_service, db_session):
    # Arrange
    user_id = 1
    current_time = datetime.now(timezone.utc)
    
    # Create more sessions than the limit (5 by default)
    sessions = []
    for i in range(6):
        session = Session(
            user_id=user_id,
            jti=f"jti_{i}",
            refresh_token_hash=f"hash_{i}",
            expires_at=current_time + timedelta(days=1),
            last_activity_at=current_time - timedelta(minutes=i),
        )
        sessions.append(session)
    
    session_service.get_user_active_sessions = AsyncMock(return_value=sessions)
    session_service.revoke_session = AsyncMock()

    # Act
    await session_service._enforce_session_limits(user_id)

    # Assert
    session_service.revoke_session.assert_called_once()
    # Should revoke the oldest session (highest minutes ago)
    called_jti = session_service.revoke_session.call_args[0][0]
    assert called_jti == "jti_5"  # Oldest session


@pytest.mark.asyncio
async def test_revoke_session_internationalization_english(session_service, db_session):
    """Test that revoke_session properly handles English internationalization."""
    # Arrange
    db_session.exec.return_value.first = MagicMock(return_value=None)

    # Act & Assert - Test with English language
    with pytest.raises(AuthenticationError) as exc_info:
        await session_service.revoke_session("non_existent_jti", 1, "en")

    # Verify the error message is in English
    expected_message = get_translated_message("session_revoked_or_invalid", "en")
    assert expected_message in str(exc_info.value)


@pytest.mark.asyncio
async def test_revoke_session_internationalization_spanish(session_service, db_session):
    """Test that revoke_session properly handles Spanish internationalization."""
    # Arrange
    db_session.exec.return_value.first = MagicMock(return_value=None)

    # Act & Assert - Test with Spanish language
    with pytest.raises(AuthenticationError) as exc_info:
        await session_service.revoke_session("non_existent_jti", 1, "es")

    # Verify the error message is in Spanish
    expected_message = get_translated_message("session_revoked_or_invalid", "es")
    assert expected_message in str(exc_info.value)
    # Should be "Sesión revocada o inválida"
    assert "Sesión revocada o inválida" in str(exc_info.value)


@pytest.mark.asyncio
async def test_revoke_session_internationalization_persian(session_service, db_session):
    """Test that revoke_session properly handles Persian internationalization."""
    # Arrange
    db_session.exec.return_value.first = MagicMock(return_value=None)

    # Act & Assert - Test with Persian language
    with pytest.raises(AuthenticationError) as exc_info:
        await session_service.revoke_session("non_existent_jti", 1, "fa")

    # Verify the error message is in Persian
    expected_message = get_translated_message("session_revoked_or_invalid", "fa")
    assert expected_message in str(exc_info.value)
    # Should be "نشست لغو شده یا نامعتبر است"
    assert "نشست لغو شده یا نامعتبر است" in str(exc_info.value)


@pytest.mark.asyncio
async def test_revoke_session_internationalization_arabic(session_service, db_session):
    """Test that revoke_session properly handles Arabic internationalization."""
    # Arrange
    db_session.exec.return_value.first = MagicMock(return_value=None)

    # Act & Assert - Test with Arabic language
    with pytest.raises(AuthenticationError) as exc_info:
        await session_service.revoke_session("non_existent_jti", 1, "ar")

    # Verify the error message is in Arabic
    expected_message = get_translated_message("session_revoked_or_invalid", "ar")
    assert expected_message in str(exc_info.value)


@pytest.mark.asyncio
async def test_revoke_session_default_language(session_service, db_session):
    """Test that revoke_session uses English as default language."""
    # Arrange
    db_session.exec.return_value.first = MagicMock(return_value=None)

    # Act & Assert - Test with default language (English)
    with pytest.raises(AuthenticationError) as exc_info:
        await session_service.revoke_session("non_existent_jti", 1)  # No language parameter

    # Should use English by default
    expected_message = get_translated_message("session_revoked_or_invalid", "en")
    assert expected_message in str(exc_info.value)


@pytest.mark.asyncio
async def test_revoke_session_invalid_language_fallback(session_service, db_session):
    """Test that revoke_session falls back to English for invalid language codes."""
    # Arrange
    db_session.exec.return_value.first = MagicMock(return_value=None)

    # Act & Assert - Test with invalid language code
    with pytest.raises(AuthenticationError) as exc_info:
        await session_service.revoke_session("non_existent_jti", 1, "invalid_lang")

    # Should fall back to English
    expected_message = get_translated_message("session_revoked_or_invalid", "en")
    assert expected_message in str(exc_info.value)


@pytest.mark.asyncio
async def test_revoke_token_internationalization_persian(session_service, db_session, redis_client):
    """Test that revoke_token properly handles Persian internationalization."""
    # Arrange
    db_session.exec.return_value.first = MagicMock(return_value=None)

    # Act & Assert - Test with Persian language
    with pytest.raises(AuthenticationError) as exc_info:
        await session_service.revoke_token("invalid_token", "fa")

    # Verify the error message is in Persian
    expected_message = get_translated_message("invalid_refresh_token", "fa")
    assert expected_message in str(exc_info.value)


@pytest.mark.asyncio
async def test_revoke_token_internationalization_spanish(session_service, db_session, redis_client):
    """Test that revoke_token properly handles Spanish internationalization."""
    # Arrange
    db_session.exec.return_value.first = MagicMock(return_value=None)

    # Act & Assert - Test with Spanish language
    with pytest.raises(AuthenticationError) as exc_info:
        await session_service.revoke_token("invalid_token", "es")

    # Verify the error message is in Spanish
    expected_message = get_translated_message("invalid_refresh_token", "es")
    assert expected_message in str(exc_info.value)


@pytest.mark.asyncio
async def test_persian_translation_demonstration():
    """Demonstrate Persian translation functionality."""
    # Test Persian translation for session-related messages
    persian_session_invalid = get_translated_message("session_revoked_or_invalid", "fa")
    assert "نشست" in persian_session_invalid  # "Session" in Persian
    
    persian_invalid_token = get_translated_message("invalid_refresh_token", "fa")
    assert "توکن" in persian_invalid_token or "نشست" in persian_invalid_token  # "Token" or "Session" in Persian
