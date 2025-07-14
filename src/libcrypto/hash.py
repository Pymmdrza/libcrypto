"""
Internal Cryptographic Hash and KDF Utilities.
This module provides wrappers around pycryptodome for hashing algorithms
and key derivation functions used within the library.
"""
from Crypto.Hash import SHA256, SHA512, RIPEMD160, keccak, HMAC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes as secure_random_bytes


def hmac_sha512(key: bytes, message: bytes) -> bytes:
    """
    Compute HMAC-SHA512 using pycryptodome.

    Args:
        key: Secret key bytes.
        message: Message bytes to authenticate.

    Returns:
        HMAC-SHA512 digest bytes (64 bytes).
    """
    h = HMAC.new(key, digestmod=SHA512)
    h.update(message)
    return h.digest()


def pbkdf2_hmac_sha512(password: bytes, salt: bytes, iterations: int, dk_length: int) -> bytes:
    """
    PBKDF2 key derivation using HMAC-SHA512 with pycryptodome.

    Args:
        password: Password bytes.
        salt: Salt bytes.
        iterations: Number of iterations.
        dk_length: Desired key length in bytes.

    Returns:
        Derived key bytes of specified length.
    """
    return PBKDF2(password, salt, dk_length, count=iterations, hmac_hash_module=SHA512)


def sha256(data: bytes) -> bytes:
    """
    Compute SHA256 hash using pycryptodome.
    """
    h = SHA256.new(data)
    return h.digest()


def ripemd160(data: bytes) -> bytes:
    """
    Compute RIPEMD160 hash using pycryptodome.
    """
    h = RIPEMD160.new(data)
    return h.digest()


def hash160(data: bytes) -> bytes:
    """
    Compute RIPEMD160(SHA256(data)) - common in Bitcoin.
    """
    return ripemd160(sha256(data))


def double_sha256(data: bytes) -> bytes:
    """
    Compute double SHA256 (SHA256(SHA256(data))) - common in Bitcoin.
    """
    return sha256(sha256(data))


def keccak256(data: bytes) -> bytes:
    """
    Compute Keccak-256 hash using pycryptodome.
    """
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def bip39_pbkdf2(mnemonic: str, passphrase: str = "") -> bytes:
    """
    BIP39-specific PBKDF2 for converting mnemonic to seed.
    """
    from .constants import PBKDF2_ITERATIONS, PBKDF2_HMAC_DKLEN
    salt = ("mnemonic" + passphrase).encode('utf-8')
    return pbkdf2_hmac_sha512(mnemonic.encode('utf-8'), salt, PBKDF2_ITERATIONS, PBKDF2_HMAC_DKLEN)
