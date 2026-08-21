import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def calculate_sha256(data: bytes) -> str:
    """
    Calculate SHA-256 hash of file data.
    """
    return hashlib.sha256(data).hexdigest()


def generate_aes_key() -> bytes:
    """
    Generate a cryptographically secure 256-bit AES key.
    """
    return AESGCM.generate_key(bit_length=256)


def encrypt_file(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt file data using AES-256-GCM.

    Returns:
        encrypted_data
        nonce
    """

    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes")

    # 96-bit nonce is recommended for GCM
    nonce = os.urandom(12)

    aesgcm = AESGCM(key)

    encrypted_data = aesgcm.encrypt(
        nonce,
        data,
        None
    )

    return encrypted_data, nonce


def decrypt_file(
    encrypted_data: bytes,
    key: bytes,
    nonce: bytes
) -> bytes:
    """
    Decrypt AES-256-GCM encrypted data.
    """

    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes")

    aesgcm = AESGCM(key)

    return aesgcm.decrypt(
        nonce,
        encrypted_data,
        None
    )