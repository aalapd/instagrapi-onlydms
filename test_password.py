import pytest
from unittest.mock import MagicMock, patch
import base64
import time

from instagrapi.mixins.password import PasswordMixin
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES


class MockResponse:
    def __init__(self, headers):
        self.headers = headers

    def json(self):
        return {}

    def raise_for_status(self):
        pass


class MockRSAKey:
    """Improved mock RSA key that provides deterministic but unique encryption."""
    def __init__(self):
        self._key_size = 256  # 2048 bits

    def size_in_bytes(self):
        return self._key_size

    def _encrypt(self, data_int):
        # Return deterministic but unique encrypted data based on input
        # This ensures different inputs produce different outputs
        return data_int.to_bytes(self._key_size, byteorder='big')


class MockAES:
    """Mock AES cipher that provides deterministic encryption and authentication."""
    def __init__(self, key, mode, nonce):
        self.key = key
        self.mode = mode
        self.nonce = nonce
        self.update_data = None

    def update(self, data):
        self.update_data = data
        return self

    def encrypt_and_digest(self, data):
        # Return deterministic but unique encrypted data and tag
        mock_encrypted = bytes([i ^ self.key[0] for i in data])
        mock_tag = bytes([i ^ self.key[-1] for i in data[:16]])
        return mock_encrypted, mock_tag


def mock_get_random_bytes(length):
    """Return deterministic 'random' bytes for testing."""
    return bytes([i % 256 for i in range(length)])


@pytest.fixture
def password_mixin():
    mixin = PasswordMixin()
    mixin.public = MagicMock()
    return mixin


@pytest.fixture
def mock_time(monkeypatch):
    """Fix time for deterministic testing."""
    fixed_time = 1612345678
    monkeypatch.setattr(time, 'time', lambda: fixed_time)
    return fixed_time


@pytest.fixture
def mock_encryption(monkeypatch):
    """Set up deterministic encryption for testing."""
    monkeypatch.setattr('Cryptodome.Random.get_random_bytes', mock_get_random_bytes)
    monkeypatch.setattr(RSA, 'import_key', MagicMock(return_value=MockRSAKey()))
    monkeypatch.setattr('Cryptodome.Cipher.AES.new', lambda key, mode, nonce: MockAES(key, mode, nonce))
    return mock_get_random_bytes


def test_password_encrypt_format(password_mixin, mock_time, mock_encryption):
    """Test password_encrypt output format and structure."""
    mock_headers = {
        "ig-set-password-encryption-key-id": "123",
        "ig-set-password-encryption-pub-key": base64.b64encode(b"mock_public_key").decode()
    }
    mock_response = MockResponse(headers=mock_headers)
    password_mixin.public.get.return_value = mock_response

    test_password = "testpassword123"
    encrypted_password = password_mixin.password_encrypt(test_password)

    # Test basic format
    assert isinstance(encrypted_password, str), "Should return a string"
    assert encrypted_password.startswith("#PWD_INSTAGRAM:4:"), "Should start with #PWD_INSTAGRAM:4:"

    # Test parts structure
    parts = encrypted_password.split(":")
    assert len(parts) == 3, "Should have 3 parts separated by colons"
    version, timestamp, payload = parts

    # Test timestamp
    assert timestamp == str(mock_time), "Should use current timestamp"

    # Test payload structure
    decoded_payload = base64.b64decode(payload)
    assert decoded_payload[0] == 1, "First byte should be version 1"
    assert decoded_payload[1] == 123, "Second byte should be public key ID"
    
    # Test IV (12 bytes), size buffer (2 bytes), RSA encrypted session key, tag, and encrypted password
    iv = decoded_payload[2:14]
    size_buffer = decoded_payload[14:16]
    rsa_size = int.from_bytes(size_buffer, byteorder="little")
    rsa_encrypted = decoded_payload[16:16+rsa_size]
    tag = decoded_payload[16+rsa_size:16+rsa_size+16]
    aes_encrypted = decoded_payload[16+rsa_size+16:]

    assert len(iv) == 12, "IV should be 12 bytes"
    assert len(rsa_encrypted) == rsa_size, "RSA encrypted data size should match size_buffer"
    assert len(tag) == 16, "Authentication tag should be 16 bytes"
    assert len(aes_encrypted) > 0, "Encrypted password should not be empty"


def test_password_encrypt_different_passwords(password_mixin, mock_time, mock_encryption):
    """Test different passwords produce different outputs with deterministic mocks."""
    mock_headers = {
        "ig-set-password-encryption-key-id": "123",
        "ig-set-password-encryption-pub-key": base64.b64encode(b"mock_public_key").decode()
    }
    mock_response = MockResponse(headers=mock_headers)
    password_mixin.public.get.return_value = mock_response

    password_1 = "password123"
    password_2 = "different456"

    encrypted_1 = password_mixin.password_encrypt(password_1)
    encrypted_2 = password_mixin.password_encrypt(password_2)

    # Extract and compare the encrypted parts
    payload_1 = base64.b64decode(encrypted_1.split(":")[2])
    payload_2 = base64.b64decode(encrypted_2.split(":")[2])
    
    # The payloads should be different due to different passwords
    assert payload_1 != payload_2, "Different passwords should produce different encrypted payloads"
    
    # But they should have the same structure
    assert len(payload_1) > 0 and len(payload_2) > 0, "Both payloads should not be empty"
    assert payload_1[0] == payload_2[0] == 1, "Both should have version 1"
    assert payload_1[1] == payload_2[1], "Both should have same public key ID"


def test_password_publickeys_retrieval(password_mixin):
    """Test password_publickeys retrieval and parsing."""
    mock_headers = {
        "ig-set-password-encryption-key-id": "123",
        "ig-set-password-encryption-pub-key": "test_public_key_base64"
    }
    mock_response = MockResponse(headers=mock_headers)
    password_mixin.public.get.return_value = mock_response

    publickeyid, publickey = password_mixin.password_publickeys()

    password_mixin.public.get.assert_called_once_with('https://i.instagram.com/api/v1/qe/sync/')
    assert publickeyid == 123, "Public key ID should be extracted as integer"
    assert publickey == "test_public_key_base64", "Public key should be extracted as string"


def test_password_encrypt_with_various_lengths(password_mixin, mock_time, mock_encryption):
    """Test encryption with passwords of different lengths."""
    mock_headers = {
        "ig-set-password-encryption-key-id": "123",
        "ig-set-password-encryption-pub-key": base64.b64encode(b"mock_public_key").decode()
    }
    mock_response = MockResponse(headers=mock_headers)
    password_mixin.public.get.return_value = mock_response

    test_passwords = ["a", "ab"*8, "c"*16, "d"*32]
    
    for password in test_passwords:
        encrypted = password_mixin.password_encrypt(password)
        parts = encrypted.split(":")
        assert len(parts) == 3, f"Password length {len(password)} should produce valid format"
        
        payload = base64.b64decode(parts[2])
        assert len(payload) > 16 + 256, "Payload should contain all required components"


def test_password_encrypt_timestamp_update(password_mixin, mock_encryption):
    """Test that timestamp updates properly in encrypted output."""
    mock_headers = {
        "ig-set-password-encryption-key-id": "123",
        "ig-set-password-encryption-pub-key": base64.b64encode(b"mock_public_key").decode()
    }
    mock_response = MockResponse(headers=mock_headers)
    password_mixin.public.get.return_value = mock_response

    test_password = "test123"
    
    # First encryption
    with patch('time.time', return_value=1000000):
        encrypted1 = password_mixin.password_encrypt(test_password)
        timestamp1 = encrypted1.split(":")[1]
        assert timestamp1 == "1000000"
    
    # Second encryption with different time
    with patch('time.time', return_value=1000001):
        encrypted2 = password_mixin.password_encrypt(test_password)
        timestamp2 = encrypted2.split(":")[1]
        assert timestamp2 == "1000001"
        
    # Verify timestamps are different but format is preserved
    assert timestamp1 != timestamp2
    assert encrypted1.startswith("#PWD_INSTAGRAM:4:")
    assert encrypted2.startswith("#PWD_INSTAGRAM:4:")
