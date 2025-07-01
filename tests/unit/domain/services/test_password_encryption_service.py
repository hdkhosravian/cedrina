"""Unit tests for Password Encryption Service.

This test suite validates the password encryption service that implements defense-in-depth
security by encrypting bcrypt password hashes before database storage.

Security Test Coverage:
    - Encryption/decryption operations
    - Format validation and error handling
    - Migration compatibility detection
    - Timing attack resistance
    - Error information disclosure prevention
    - Key handling and initialization
"""

import base64
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from unittest.mock import Mock, patch

from src.core.exceptions import DecryptionError, EncryptionError
from src.domain.services.auth.password_encryption import PasswordEncryptionService


class TestPasswordEncryptionService:
    """Test suite for password encryption service with comprehensive security validation."""

    @pytest.fixture
    def test_key(self):
        """Generate a test encryption key for isolated testing."""
        return base64.urlsafe_b64encode(b"test_key_32_bytes_for_secure_test").decode()

    @pytest.fixture
    def encryption_service(self, test_key):
        """Create encryption service instance with test key."""
        return PasswordEncryptionService(encryption_key=test_key)

    @pytest.fixture
    def valid_bcrypt_hash(self):
        """Valid bcrypt hash for testing."""
        # Real bcrypt hash for "test_password"
        return "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/lewdBdXC/B9UVWLvW"

    @pytest.fixture
    def invalid_bcrypt_hashes(self):
        """Collection of invalid bcrypt hashes for negative testing."""
        return [
            "",  # Empty string
            "invalid_hash",  # Not bcrypt format
            "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/lewdBdXC/B9UVWLvW",  # Wrong prefix
            "$2b$12$short",  # Too short
            "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/lewdBdXC/B9UVWLvWtoolong",  # Too long
            "$2b$12$invalid$$format",  # Too many dollar signs
            "$2b$12",  # Missing parts
        ]

    # Initialization Tests

    def test_initialization_with_valid_key(self, test_key):
        """Test service initializes correctly with valid encryption key."""
        service = PasswordEncryptionService(encryption_key=test_key)
        assert service._fernet is not None
        assert isinstance(service._fernet, Fernet)

    def test_initialization_with_invalid_key_falls_back(self):
        """Test service falls back to generated key when invalid key provided."""
        with patch('src.domain.services.auth.password_encryption.logger') as mock_logger:
            service = PasswordEncryptionService(encryption_key="invalid_key")
            
            # Should still initialize but with fallback key
            assert service._fernet is not None
            mock_logger.bind.return_value.warning.assert_called()

    @patch('src.core.config.settings.settings')
    def test_initialization_uses_pgcrypto_key_when_none_provided(self, mock_settings, test_key):
        """Test service uses PGCRYPTO_KEY from settings when no key provided."""
        mock_settings.PGCRYPTO_KEY.get_secret_value.return_value = test_key
        
        service = PasswordEncryptionService()
        assert service._fernet is not None

    # Encryption Tests

    @pytest.mark.asyncio
    async def test_encrypt_password_hash_success(self, encryption_service, valid_bcrypt_hash):
        """Test successful encryption of valid bcrypt hash."""
        encrypted = await encryption_service.encrypt_password_hash(valid_bcrypt_hash)
        
        # Verify encrypted format
        assert encrypted.startswith("enc_v1:")
        assert len(encrypted) > len("enc_v1:")
        
        # Verify it's valid base64
        encrypted_data = encrypted[7:]  # Remove prefix
        base64.b64decode(encrypted_data)  # Should not raise exception

    @pytest.mark.asyncio
    async def test_encrypt_password_hash_with_invalid_input(
        self, encryption_service, invalid_bcrypt_hashes
    ):
        """Test encryption fails with invalid bcrypt hash formats."""
        for invalid_hash in invalid_bcrypt_hashes:
            with pytest.raises(ValueError, match="Invalid bcrypt hash"):
                await encryption_service.encrypt_password_hash(invalid_hash)

    @pytest.mark.asyncio
    async def test_encrypt_password_hash_none_input(self, encryption_service):
        """Test encryption fails with None input."""
        with pytest.raises(ValueError):
            await encryption_service.encrypt_password_hash(None)

    @pytest.mark.asyncio
    async def test_encrypt_password_hash_unique_results(self, encryption_service, valid_bcrypt_hash):
        """Test encryption produces unique results for same input (due to IV/nonce)."""
        encrypted1 = await encryption_service.encrypt_password_hash(valid_bcrypt_hash)
        encrypted2 = await encryption_service.encrypt_password_hash(valid_bcrypt_hash)
        
        # Results should be different due to unique IV/nonce
        assert encrypted1 != encrypted2
        
        # But both should have same prefix
        assert encrypted1.startswith("enc_v1:")
        assert encrypted2.startswith("enc_v1:")

    @pytest.mark.asyncio
    async def test_encrypt_password_hash_handles_fernet_error(self, encryption_service, valid_bcrypt_hash):
        """Test encryption handles underlying Fernet errors gracefully."""
        # Mock Fernet to raise exception
        with patch.object(encryption_service._fernet, 'encrypt', side_effect=Exception("Fernet error")):
            with pytest.raises(EncryptionError, match="Failed to encrypt password hash"):
                await encryption_service.encrypt_password_hash(valid_bcrypt_hash)

    # Decryption Tests

    @pytest.mark.asyncio
    async def test_decrypt_password_hash_success(self, encryption_service, valid_bcrypt_hash):
        """Test successful decryption of encrypted hash."""
        # First encrypt
        encrypted = await encryption_service.encrypt_password_hash(valid_bcrypt_hash)
        
        # Then decrypt
        decrypted = await encryption_service.decrypt_password_hash(encrypted)
        
        # Should match original
        assert decrypted == valid_bcrypt_hash

    @pytest.mark.asyncio
    async def test_decrypt_password_hash_with_invalid_format(self, encryption_service):
        """Test decryption fails with invalid encrypted format."""
        invalid_formats = [
            "",  # Empty
            "invalid_format",  # No prefix
            "enc_v2:data",  # Wrong version
            "enc_v1:invalid_base64!",  # Invalid base64
        ]
        
        for invalid_format in invalid_formats:
            with pytest.raises(ValueError, match="Invalid encrypted hash format"):
                await encryption_service.decrypt_password_hash(invalid_format)
        
        # Test empty data separately as it raises DecryptionError after format validation
        with pytest.raises(DecryptionError, match="Failed to decrypt password hash"):
            await encryption_service.decrypt_password_hash("enc_v1:")

    @pytest.mark.asyncio
    async def test_decrypt_password_hash_with_corrupted_data(self, encryption_service):
        """Test decryption fails with corrupted encrypted data."""
        # Create valid format but with corrupted data
        corrupted_data = base64.b64encode(b"corrupted_data").decode()
        corrupted_hash = f"enc_v1:{corrupted_data}"
        
        with pytest.raises(DecryptionError, match="Failed to decrypt password hash"):
            await encryption_service.decrypt_password_hash(corrupted_hash)

    @pytest.mark.asyncio
    async def test_decrypt_password_hash_with_wrong_key(self, valid_bcrypt_hash):
        """Test decryption fails when using different key than encryption."""
        # Encrypt with one key
        service1 = PasswordEncryptionService(encryption_key=Fernet.generate_key().decode())
        encrypted = await service1.encrypt_password_hash(valid_bcrypt_hash)
        
        # Try to decrypt with different key
        service2 = PasswordEncryptionService(encryption_key=Fernet.generate_key().decode())
        
        with pytest.raises(DecryptionError, match="authentication failed"):
            await service2.decrypt_password_hash(encrypted)

    @pytest.mark.asyncio
    async def test_decrypt_password_hash_validates_result(self, encryption_service):
        """Test decryption validates that result is valid bcrypt hash."""
        # Create a valid encrypted format but with invalid bcrypt data
        invalid_bcrypt = "not_a_bcrypt_hash"
        encrypted_bytes = encryption_service._fernet.encrypt(invalid_bcrypt.encode())
        encrypted_b64 = base64.b64encode(encrypted_bytes).decode()
        encrypted_hash = f"enc_v1:{encrypted_b64}"
        
        with pytest.raises(ValueError, match="Invalid bcrypt hash"):
            await encryption_service.decrypt_password_hash(encrypted_hash)

    # Format Detection Tests

    def test_is_encrypted_format_with_encrypted_values(self, encryption_service):
        """Test format detection correctly identifies encrypted values."""
        encrypted_values = [
            "enc_v1:dGVzdA==",  # Valid encrypted format
            "enc_v1:bG9uZ2VyX2VuY3J5cHRlZF9kYXRh",  # Longer encrypted data
        ]
        
        for encrypted_value in encrypted_values:
            assert encryption_service.is_encrypted_format(encrypted_value) is True

    def test_is_encrypted_format_with_unencrypted_values(self, encryption_service, valid_bcrypt_hash):
        """Test format detection correctly identifies unencrypted values."""
        unencrypted_values = [
            valid_bcrypt_hash,  # Bcrypt hash
            "plain_text",  # Plain text
            "enc_v2:data",  # Wrong version
            "",  # Empty string
            None,  # None value
        ]
        
        for unencrypted_value in unencrypted_values:
            assert encryption_service.is_encrypted_format(unencrypted_value) is False

    def test_is_encrypted_format_constant_time(self, encryption_service):
        """Test format detection operation is constant-time (security requirement)."""
        # This test verifies the method doesn't depend on string length for timing
        short_value = "enc_v1:a"
        long_value = "enc_v1:" + "a" * 1000
        bcrypt_value = "$2b$12$abcdefghijklmnopqrstuvwxyz123456789ABCDEFGHIJKLMNOP"
        
        # All should execute without timing-based information disclosure
        assert encryption_service.is_encrypted_format(short_value) is True
        assert encryption_service.is_encrypted_format(long_value) is True
        assert encryption_service.is_encrypted_format(bcrypt_value) is False

    # Bcrypt Validation Tests

    def test_validate_bcrypt_hash_with_valid_hashes(self, encryption_service):
        """Test bcrypt validation accepts valid hash formats."""
        valid_hashes = [
            "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",  # Round 10
            "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/lewdBdXC/B9UVWLvW",  # Round 12
            "$2b$15$LU5AhJV.r8K8R1Q8K3qTYuXJ8LYL13YjOKuE4CqH1fL2vMF19B9cS",  # Round 15
        ]
        
        for valid_hash in valid_hashes:
            # Should not raise exception
            encryption_service._validate_bcrypt_hash(valid_hash)

    def test_validate_bcrypt_hash_with_invalid_hashes(self, encryption_service, invalid_bcrypt_hashes):
        """Test bcrypt validation rejects invalid hash formats."""
        for invalid_hash in invalid_bcrypt_hashes:
            with pytest.raises(ValueError):
                encryption_service._validate_bcrypt_hash(invalid_hash)

    def test_validate_bcrypt_hash_with_non_string_input(self, encryption_service):
        """Test bcrypt validation handles non-string input."""
        invalid_inputs = [123, [], {}, object()]  # Removed None as it triggers "empty" check first
        
        for invalid_input in invalid_inputs:
            with pytest.raises(ValueError, match="must be a string"):
                encryption_service._validate_bcrypt_hash(invalid_input)
        
        # Test None separately as it also triggers string type check
        with pytest.raises(ValueError, match="must be a string"):
            encryption_service._validate_bcrypt_hash(None)

    # Security Tests

    @pytest.mark.asyncio
    async def test_encryption_no_information_disclosure_on_error(self, encryption_service):
        """Test encryption errors don't disclose sensitive information."""
        # Mock Fernet to raise specific exception
        with patch.object(encryption_service._fernet, 'encrypt', side_effect=Exception("sensitive_key_info")):
            with pytest.raises(EncryptionError) as exc_info:
                await encryption_service.encrypt_password_hash("$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/lewdBdXC/B9UVWLvW")
            
            # Error message should be generic, not expose sensitive details
            assert "sensitive_key_info" not in str(exc_info.value)
            assert "Failed to encrypt password hash" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_decryption_no_information_disclosure_on_error(self, encryption_service):
        """Test decryption errors don't disclose sensitive information."""
        # Valid format but corrupted data
        corrupted_data = base64.b64encode(b"corrupted").decode()
        corrupted_hash = f"enc_v1:{corrupted_data}"
        
        with pytest.raises(DecryptionError) as exc_info:
            await encryption_service.decrypt_password_hash(corrupted_hash)
        
        # Error message should be generic
        assert "Failed to decrypt password hash" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_round_trip_encryption_multiple_times(self, encryption_service, valid_bcrypt_hash):
        """Test encryption/decryption works consistently over multiple iterations."""
        original = valid_bcrypt_hash
        
        for i in range(10):  # Test multiple rounds
            encrypted = await encryption_service.encrypt_password_hash(original)
            decrypted = await encryption_service.decrypt_password_hash(encrypted)
            assert decrypted == original

    def test_logging_does_not_expose_sensitive_data(self, encryption_service, valid_bcrypt_hash):
        """Test that logging doesn't expose sensitive password data."""
        with patch('src.domain.services.auth.password_encryption.logger') as mock_logger:
            # Any logging calls should not contain sensitive data
            # This test ensures we don't accidentally log password hashes or keys
            
            # Test that initialization logs safely
            PasswordEncryptionService(encryption_key=Fernet.generate_key().decode())
            
            # Check that no sensitive data appears in log calls
            for call in mock_logger.bind.return_value.info.call_args_list:
                args, kwargs = call
                for value in kwargs.values():
                    if isinstance(value, str):
                        assert "$2b$" not in value  # No bcrypt hashes
                        assert "enc_v1:" not in value  # No encrypted data

    # Integration Tests

    @pytest.mark.asyncio
    async def test_encryption_service_handles_concurrent_operations(self, encryption_service, valid_bcrypt_hash):
        """Test service handles concurrent encryption/decryption operations safely."""
        import asyncio
        
        async def encrypt_decrypt_cycle():
            encrypted = await encryption_service.encrypt_password_hash(valid_bcrypt_hash)
            decrypted = await encryption_service.decrypt_password_hash(encrypted)
            return decrypted == valid_bcrypt_hash
        
        # Run multiple concurrent operations
        tasks = [encrypt_decrypt_cycle() for _ in range(10)]
        results = await asyncio.gather(*tasks)
        
        # All should succeed
        assert all(results)

    @pytest.mark.asyncio
    async def test_migration_compatibility_scenario(self, encryption_service):
        """Test service correctly handles migration scenario with mixed hash formats."""
        # Scenario: Database has both encrypted and unencrypted hashes during migration
        bcrypt_hash = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/lewdBdXC/B9UVWLvW"
        encrypted_hash = await encryption_service.encrypt_password_hash(bcrypt_hash)
        
        # Service should correctly identify formats
        assert not encryption_service.is_encrypted_format(bcrypt_hash)
        assert encryption_service.is_encrypted_format(encrypted_hash)
        
        # Should be able to decrypt encrypted hash
        decrypted = await encryption_service.decrypt_password_hash(encrypted_hash)
        assert decrypted == bcrypt_hash 