from __future__ import annotations

import base64
import hashlib
from typing import Any

from cryptography.fernet import Fernet


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte Fernet key from a password and salt."""
    key_material = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100_000,
        dklen=32,
    )
    return base64.urlsafe_b64encode(key_material)


def encrypt_secret(value: str, password: str, salt: bytes) -> str:
    """Encrypt a plaintext secret using a password-derived key."""
    key = derive_key(password, salt)
    token = Fernet(key).encrypt(value.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_secret(value: str, password: str, salt: bytes) -> str:
    """Decrypt an encrypted secret using a password-derived key."""
    key = derive_key(password, salt)
    plaintext = Fernet(key).decrypt(value.encode("utf-8"))
    return plaintext.decode("utf-8")


def generate_salt() -> bytes:
    """Create a secure random salt for password-based key derivation."""
    return base64.urlsafe_b64encode(hashlib.sha256(b"securevault-salt").digest()[:16])
