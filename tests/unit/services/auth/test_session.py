import pytest
from src.domain.entities.session import Session
from src.domain.services.auth.session import SessionService
from src.core.exceptions import DatabaseError, AuthenticationError
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone, timedelta
from src.utils.i18n import setup_i18n, get_translated_message

@pytest.fixture(scope="session", autouse=True)
def setup_i18n_for_tests():
    """Setup i18n system for all tests."""
    setup_i18n()

@pytest.fixture
def session_service(db_session, redis_client):
    """Provides a SessionService instance with mocked dependencies."""
    return SessionService(db_session, redis_client)

@pytest.mark.asyncio
async def test_create_session(session_service, db_session):
    # Arrange
    user_id = 1
    jti = "test_jti"
    refresh_token_hash = "some_hash"
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    # Act
    session = await session_service.create_session(user_id, jti, refresh_token_hash, expires_at)

    # Assert
    assert session.user_id == user_id
    assert session.jti == jti
    assert session.refresh_token_hash == refresh_token_hash
    db_session.add.assert_called_once()
    db_session.commit.assert_called_once()
    db_session.refresh.assert_called_once_with(session)

@pytest.mark.asyncio
async def test_revoke_session_success(session_service, db_session, redis_client):
    # Arrange
    user_id = 1
    jti = "test-jti"
    session = Session(user_id=user_id, jti=jti, refresh_token_hash="hashed_token")
    db_session.exec.return_value.first = MagicMock(return_value=session)

    # Act
    await session_service.revoke_session(jti, user_id, "en")

    # Assert
    assert session.revoked_at is not None
    db_session.commit.assert_called_once()
    redis_client.delete.assert_called_once_with(f"refresh_token:{jti}")

@pytest.mark.asyncio
async def test_revoke_session_not_found(session_service, db_session):
    # Arrange
    db_session.exec.return_value.first = MagicMock(return_value=None)

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Session revoked or invalid"):
        await session_service.revoke_session("non_existent_jti", 1, "en")

@pytest.mark.asyncio
async def test_is_session_valid_valid(session_service, db_session):
    # Arrange
    user_id = 1
    jti = "test-jti"
    session = Session(
        user_id=user_id,
        jti=jti,
        refresh_token_hash="hashed_token",
        expires_at=datetime.now(timezone.utc) + timedelta(days=1)
    )
    db_session.exec.return_value.first = MagicMock(return_value=session)

    # Act
    is_valid = await session_service.is_session_valid(jti, user_id)

    # Assert
    assert is_valid is True

@pytest.mark.asyncio
async def test_is_session_valid_expired(session_service, db_session):
    # Arrange
    user_id = 1
    jti = "test-jti"
    session = Session(
        user_id=user_id,
        jti=jti,
        refresh_token_hash="hashed_token",
        expires_at=datetime.now(timezone.utc) - timedelta(days=1)
    )
    db_session.exec.return_value.first = MagicMock(return_value=session)

    # Act
    is_valid = await session_service.is_session_valid(jti, user_id)

    # Assert
    assert is_valid is False

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
    from jose import jwt
    from src.core.config.settings import settings
    
    # Arrange - Create a valid JWT token
    payload = {
        "sub": "1",
        "jti": "test-jti-persian",
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "iat": datetime.now(timezone.utc),
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE
    }
    token = jwt.encode(payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256")
    
    # Mock session to be None (not found)
    db_session.exec.return_value.first = MagicMock(return_value=None)

    # Act & Assert - Test with Persian language
    with pytest.raises(AuthenticationError) as exc_info:
        await session_service.revoke_token(token, "fa")
    
    # Verify the error message is in Persian
    expected_message = get_translated_message("session_revoked_or_invalid", "fa")
    assert expected_message in str(exc_info.value)
    # Should be "نشست لغو شده یا نامعتبر است"
    assert "نشست لغو شده یا نامعتبر است" in str(exc_info.value)

@pytest.mark.asyncio
async def test_revoke_token_internationalization_spanish(session_service, db_session, redis_client):
    """Test that revoke_token properly handles Spanish internationalization."""
    from jose import jwt
    from src.core.config.settings import settings
    
    # Arrange - Create a valid JWT token
    payload = {
        "sub": "1",
        "jti": "test-jti-spanish",
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "iat": datetime.now(timezone.utc),
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE
    }
    token = jwt.encode(payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256")
    
    # Mock session to be None (not found)
    db_session.exec.return_value.first = MagicMock(return_value=None)

    # Act & Assert - Test with Spanish language
    with pytest.raises(AuthenticationError) as exc_info:
        await session_service.revoke_token(token, "es")
    
    # Verify the error message is in Spanish
    expected_message = get_translated_message("session_revoked_or_invalid", "es")
    assert expected_message in str(exc_info.value)
    # Should be "Sesión revocada o inválida"
    assert "Sesión revocada o inválida" in str(exc_info.value)

@pytest.mark.asyncio
async def test_persian_translation_demonstration():
    """Demonstration test showing actual Persian translation text."""
    # This test demonstrates that the Persian translation is working correctly
    persian_message = get_translated_message("session_revoked_or_invalid", "fa")
    english_message = get_translated_message("session_revoked_or_invalid", "en")
    spanish_message = get_translated_message("session_revoked_or_invalid", "es")
    
    # Verify we get different messages for different languages
    assert persian_message != english_message
    assert spanish_message != english_message
    assert persian_message != spanish_message
    
    # Verify the actual Persian text
    assert persian_message == "نشست لغو شده یا نامعتبر است"
    assert english_message == "Session revoked or invalid"
    assert spanish_message == "Sesión revocada o inválida"
    
    # Print for demonstration (will show in test output)
    print(f"\nPersian: {persian_message}")
    print(f"English: {english_message}")
    print(f"Spanish: {spanish_message}")