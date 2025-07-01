"""Unit tests for Enhanced Password Value Objects with Encryption Support.

This test suite validates the enhanced password value objects that support
encryption-at-rest for defense-in-depth security.

Test Coverage:
    - EncryptedPassword value object functionality
    - Enhanced HashedPassword with encryption detection
    - Migration compatibility between encrypted and unencrypted formats
    - Error handling and validation
    - Security properties and immutability
"""

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, Mock, patch

from src.core.exceptions import DecryptionError, EncryptionError
from src.domain.value_objects.password import (
    Password, 
    HashedPassword, 
    EncryptedPassword
)


class TestEnhancedHashedPassword:
    """Test suite for enhanced HashedPassword with encryption support."""

    @pytest.fixture
    def valid_bcrypt_hash(self):
        """Valid unencrypted bcrypt hash."""
        return "$2b$12$Fg6iizuEs1Du8vy1pxiyk.9s1.3u3zAxo8TjLN7vqAQL9nUHzgM9i"

    @pytest.fixture
    def valid_encrypted_hash(self):
        """Valid encrypted hash format."""
        return "enc_v1:Z2FiYWdvb2w="  # Base64 encoded "gabagool"

    def test_hashed_password_accepts_unencrypted_bcrypt(self, valid_bcrypt_hash):
        """Test HashedPassword accepts valid unencrypted bcrypt hash."""
        hashed = HashedPassword.from_hash(valid_bcrypt_hash)
        assert hashed.value == valid_bcrypt_hash
        assert not hashed.is_encrypted()

    def test_hashed_password_accepts_encrypted_hash(self, valid_encrypted_hash):
        """Test HashedPassword accepts valid encrypted hash."""
        hashed = HashedPassword.from_hash(valid_encrypted_hash)
        assert hashed.value == valid_encrypted_hash
        assert hashed.is_encrypted()

    def test_hashed_password_rejects_invalid_unencrypted_format(self):
        """Test HashedPassword rejects invalid unencrypted hash formats."""
        invalid_hashes = [
            "",  # Empty
            "invalid_hash",  # Not bcrypt
            "$2a$12$abcdefghijklmnopqrstuvwxyz123456789ABCDEFGHIJKLMNOP",  # Wrong algorithm
            "$2b$12$short",  # Too short
            "$2b$12$Fg6iizuEs1Du8vy1pxiyk.9s1.3u3zAxo8TjLN7vqAQL9nUHzgM9itoolong",  # Too long
        ]
        
        for invalid_hash in invalid_hashes:
            with pytest.raises(ValueError):
                HashedPassword.from_hash(invalid_hash)

    def test_hashed_password_rejects_invalid_encrypted_format(self):
        """Test HashedPassword rejects invalid encrypted hash formats."""
        invalid_encrypted = [
            "enc_v2:data",  # Wrong version
            "encrypted_data",  # No prefix
            "enc_v1:",  # No data
        ]
        
        for invalid in invalid_encrypted:
            with pytest.raises(ValueError):
                HashedPassword.from_hash(invalid)

    def test_hashed_password_is_encrypted_detection(self, valid_bcrypt_hash, valid_encrypted_hash):
        """Test encryption detection method works correctly."""
        unencrypted = HashedPassword.from_hash(valid_bcrypt_hash)
        encrypted = HashedPassword.from_hash(valid_encrypted_hash)
        
        assert not unencrypted.is_encrypted()
        assert encrypted.is_encrypted()

    def test_hashed_password_from_plain_password_creates_unencrypted(self):
        """Test creating HashedPassword from Password creates unencrypted hash."""
        password = Password("Rx7!mQ8$vZ2@")
        hashed = HashedPassword.from_plain_password(password)
        
        assert not hashed.is_encrypted()
        assert hashed.value.startswith("$2b$")
        assert len(hashed.value) == 60

    def test_hashed_password_immutability(self, valid_bcrypt_hash):
        """Test HashedPassword is immutable."""
        hashed = HashedPassword.from_hash(valid_bcrypt_hash)
        
        # Should not be able to modify value
        with pytest.raises(AttributeError):
            hashed.value = "modified"

    def test_hashed_password_rejects_none_value(self):
        """Test HashedPassword rejects None values."""
        with pytest.raises(ValueError, match="cannot be empty"):
            HashedPassword.from_hash("")


class TestEncryptedPassword:
    """Test suite for EncryptedPassword value object."""

    @pytest.fixture
    def valid_encrypted_value(self):
        """Valid encrypted password value."""
        return "enc_v1:Z2FiYWdvb2w="

    @pytest.fixture
    def mock_encryption_service(self):
        """Mock encryption service for testing."""
        service = AsyncMock()
        service.encrypt_password_hash = AsyncMock()
        service.decrypt_password_hash = AsyncMock()
        return service

    @pytest.fixture
    def valid_bcrypt_hash(self):
        """Valid bcrypt hash for testing."""
        return "$2b$12$Fg6iizuEs1Du8vy1pxiyk.9s1.3u3zAxo8TjLN7vqAQL9nUHzgM9i"

    def test_encrypted_password_creation_success(self, valid_encrypted_value):
        """Test successful creation of EncryptedPassword."""
        encrypted = EncryptedPassword(encrypted_value=valid_encrypted_value)
        assert encrypted.encrypted_value == valid_encrypted_value

    def test_encrypted_password_rejects_invalid_format(self):
        """Test EncryptedPassword rejects invalid formats."""
        invalid_values = [
            ("", "cannot be empty"),  # Empty
            ("invalid_format", "Invalid encrypted password format"),  # No prefix
            ("enc_v2:data", "Invalid encrypted password format"),  # Wrong version
            ("plain_text", "Invalid encrypted password format"),  # Not encrypted
        ]
        
        for invalid_value, expected_message in invalid_values:
            with pytest.raises(ValueError, match=expected_message):
                EncryptedPassword(encrypted_value=invalid_value)

    def test_encrypted_password_rejects_none_value(self):
        """Test EncryptedPassword rejects None values."""
        with pytest.raises(ValueError, match="cannot be empty"):
            EncryptedPassword(encrypted_value="")

    @pytest.mark.asyncio
    async def test_from_hashed_password_with_unencrypted_hash(
        self, valid_bcrypt_hash, mock_encryption_service
    ):
        """Test creating EncryptedPassword from unencrypted HashedPassword."""
        # Setup mock
        encrypted_result = "enc_v1:encrypted_data"
        mock_encryption_service.encrypt_password_hash.return_value = encrypted_result
        
        hashed = HashedPassword.from_hash(valid_bcrypt_hash)
        
        # Create encrypted password
        encrypted = await EncryptedPassword.from_hashed_password(hashed, mock_encryption_service)
        
        assert encrypted.encrypted_value == encrypted_result
        mock_encryption_service.encrypt_password_hash.assert_called_once_with(valid_bcrypt_hash)

    @pytest.mark.asyncio
    async def test_from_hashed_password_with_already_encrypted_hash(
        self, mock_encryption_service
    ):
        """Test creating EncryptedPassword from already encrypted HashedPassword."""
        encrypted_hash_value = "enc_v1:already_encrypted"
        hashed = HashedPassword.from_hash(encrypted_hash_value)
        
        # Should return as-is without re-encryption
        encrypted = await EncryptedPassword.from_hashed_password(hashed, mock_encryption_service)
        
        assert encrypted.encrypted_value == encrypted_hash_value
        mock_encryption_service.encrypt_password_hash.assert_not_called()

    @pytest.mark.asyncio
    async def test_from_hashed_password_handles_encryption_error(
        self, valid_bcrypt_hash, mock_encryption_service
    ):
        """Test from_hashed_password handles encryption errors."""
        mock_encryption_service.encrypt_password_hash.side_effect = EncryptionError("Encryption failed")
        
        hashed = HashedPassword.from_hash(valid_bcrypt_hash)
        
        with pytest.raises(EncryptionError):
            await EncryptedPassword.from_hashed_password(hashed, mock_encryption_service)

    @pytest.mark.asyncio
    async def test_to_bcrypt_hash_success(self, valid_encrypted_value, mock_encryption_service):
        """Test successful decryption to bcrypt hash."""
        decrypted_hash = "$2b$12$Fg6iizuEs1Du8vy1pxiyk.9s1.3u3zAxo8TjLN7vqAQL9nUHzgM9i"
        mock_encryption_service.decrypt_password_hash.return_value = decrypted_hash
        
        encrypted = EncryptedPassword(encrypted_value=valid_encrypted_value)
        result = await encrypted.to_bcrypt_hash(mock_encryption_service)
        
        assert result == decrypted_hash
        mock_encryption_service.decrypt_password_hash.assert_called_once_with(valid_encrypted_value)

    @pytest.mark.asyncio
    async def test_to_bcrypt_hash_handles_decryption_error(
        self, valid_encrypted_value, mock_encryption_service
    ):
        """Test to_bcrypt_hash handles decryption errors."""
        mock_encryption_service.decrypt_password_hash.side_effect = DecryptionError("Decryption failed")
        
        encrypted = EncryptedPassword(encrypted_value=valid_encrypted_value)
        
        with pytest.raises(DecryptionError):
            await encrypted.to_bcrypt_hash(mock_encryption_service)

    def test_get_storage_value(self, valid_encrypted_value):
        """Test get_storage_value returns encrypted value for database storage."""
        encrypted = EncryptedPassword(encrypted_value=valid_encrypted_value)
        assert encrypted.get_storage_value() == valid_encrypted_value

    def test_encrypted_password_immutability(self, valid_encrypted_value):
        """Test EncryptedPassword is immutable."""
        encrypted = EncryptedPassword(encrypted_value=valid_encrypted_value)
        
        # Should not be able to modify value
        with pytest.raises(AttributeError):
            encrypted.encrypted_value = "modified"

    def test_encrypted_password_string_representation(self, valid_encrypted_value):
        """Test EncryptedPassword has proper string representation."""
        encrypted = EncryptedPassword(encrypted_value=valid_encrypted_value)
        
        # Should have meaningful repr but not expose sensitive data
        repr_str = repr(encrypted)
        assert "EncryptedPassword" in repr_str
        # Should not contain the actual encrypted value for security
        assert valid_encrypted_value not in repr_str


class TestPasswordValueObjectsIntegration:
    """Integration tests for password value objects working together."""

    @pytest.fixture
    def mock_encryption_service(self):
        """Mock encryption service for testing."""
        service = AsyncMock()
        return service

    @pytest.mark.asyncio
    async def test_password_to_encrypted_password_flow(self, mock_encryption_service):
        """Test complete flow from Password to EncryptedPassword."""
        # Setup mock
        encrypted_result = "enc_v1:encrypted_bcrypt_hash"
        mock_encryption_service.encrypt_password_hash.return_value = encrypted_result
        
        # Create password and hash it
        password = Password("Rx7!mQ8$vZ2@")
        hashed = password.to_hashed()
        
        # Convert to encrypted password
        encrypted = await EncryptedPassword.from_hashed_password(hashed, mock_encryption_service)
        
        assert encrypted.encrypted_value == encrypted_result
        mock_encryption_service.encrypt_password_hash.assert_called_once()

    @pytest.mark.asyncio
    async def test_encrypted_password_round_trip(self, mock_encryption_service):
        """Test encrypting and then decrypting password hash."""
        original_bcrypt = "$2b$12$Fg6iizuEs1Du8vy1pxiyk.9s1.3u3zAxo8TjLN7vqAQL9nUHzgM9i"
        encrypted_value = "enc_v1:encrypted_data"
        
        # Setup mocks
        mock_encryption_service.encrypt_password_hash.return_value = encrypted_value
        mock_encryption_service.decrypt_password_hash.return_value = original_bcrypt
        
        # Create hashed password and encrypt it
        hashed = HashedPassword.from_hash(original_bcrypt)
        encrypted = await EncryptedPassword.from_hashed_password(hashed, mock_encryption_service)
        
        # Decrypt back to bcrypt hash
        decrypted_bcrypt = await encrypted.to_bcrypt_hash(mock_encryption_service)
        
        assert decrypted_bcrypt == original_bcrypt

    def test_migration_compatibility_detection(self):
        """Test value objects correctly detect migration states."""
        bcrypt_hash = "$2b$12$Fg6iizuEs1Du8vy1pxiyk.9s1.3u3zAxo8TjLN7vqAQL9nUHzgM9i"
        encrypted_hash = "enc_v1:encrypted_data"
        
        # Test HashedPassword detection
        unencrypted_hashed = HashedPassword.from_hash(bcrypt_hash)
        encrypted_hashed = HashedPassword.from_hash(encrypted_hash)
        
        assert not unencrypted_hashed.is_encrypted()
        assert encrypted_hashed.is_encrypted()

    @pytest.mark.asyncio
    async def test_error_propagation_through_value_objects(self, mock_encryption_service):
        """Test error propagation through value object operations."""
        # Test encryption error propagation
        mock_encryption_service.encrypt_password_hash.side_effect = EncryptionError("Encryption failed")
        
        hashed = HashedPassword.from_hash("$2b$12$Fg6iizuEs1Du8vy1pxiyk.9s1.3u3zAxo8TjLN7vqAQL9nUHzgM9i")
        
        with pytest.raises(EncryptionError):
            await EncryptedPassword.from_hashed_password(hashed, mock_encryption_service)
        
        # Test decryption error propagation
        mock_encryption_service.decrypt_password_hash.side_effect = DecryptionError("Decryption failed")
        
        encrypted = EncryptedPassword(encrypted_value="enc_v1:test_data")
        
        with pytest.raises(DecryptionError):
            await encrypted.to_bcrypt_hash(mock_encryption_service)

    def test_value_object_equality_and_hashing(self):
        """Test value objects support equality comparison and hashing."""
        hash1 = "$2b$12$Fg6iizuEs1Du8vy1pxiyk.9s1.3u3zAxo8TjLN7vqAQL9nUHzgM9i"
        hash2 = "$2b$12$Fg6iizuEs1Du8vy1pxiyk.rdFNiLRzOd9Sg.LZOOp4TQEaIChP2By"
        
        # Test HashedPassword equality
        hashed1a = HashedPassword.from_hash(hash1)
        hashed1b = HashedPassword.from_hash(hash1)
        hashed2 = HashedPassword.from_hash(hash2)
        
        assert hashed1a == hashed1b
        assert hashed1a != hashed2
        
        # Test EncryptedPassword equality
        encrypted1a = EncryptedPassword(encrypted_value="enc_v1:data1")
        encrypted1b = EncryptedPassword(encrypted_value="enc_v1:data1")
        encrypted2 = EncryptedPassword(encrypted_value="enc_v1:data2")
        
        assert encrypted1a == encrypted1b
        assert encrypted1a != encrypted2

    def test_value_objects_are_serializable(self):
        """Test value objects can be serialized for logging/debugging."""
        hashed = HashedPassword.from_hash("$2b$12$Fg6iizuEs1Du8vy1pxiyk.9s1.3u3zAxo8TjLN7vqAQL9nUHzgM9i")
        encrypted = EncryptedPassword(encrypted_value="enc_v1:test_data")
        
        # Should be able to convert to string for logging
        str(hashed)
        str(encrypted)
        
        # Should have meaningful representations
        assert "HashedPassword" in repr(hashed)
        assert "EncryptedPassword" in repr(encrypted) 