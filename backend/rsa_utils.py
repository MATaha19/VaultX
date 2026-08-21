import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def generate_rsa_key_pair():
    """
    Generate an RSA-2048 public/private key pair.
    """

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return (
        base64.b64encode(public_pem).decode("utf-8"),
        base64.b64encode(private_pem).decode("utf-8"),
    )


def encrypt_aes_key(
    aes_key: bytes,
    public_key_b64: str,
) -> str:
    """
    Encrypt the AES key using the recipient's RSA public key.
    """

    public_pem = base64.b64decode(public_key_b64)

    public_key = serialization.load_pem_public_key(
        public_pem
    )

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return base64.b64encode(
        encrypted_key
    ).decode("utf-8")


def decrypt_aes_key(
    encrypted_key_b64: str,
    private_key_b64: str,
) -> bytes:
    """
    Decrypt the AES key using the recipient's RSA private key.
    """

    private_pem = base64.b64decode(private_key_b64)

    private_key = serialization.load_pem_private_key(
        private_pem,
        password=None,
    )

    encrypted_key = base64.b64decode(
        encrypted_key_b64
    )

    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )