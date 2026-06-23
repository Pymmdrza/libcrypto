"""Internal cryptographic hash and KDF utilities.

This module intentionally uses only Python's standard library plus small
pure-Python primitives shipped inside libcrypto. No external cryptography
package is required at runtime.
"""
from __future__ import annotations

import hashlib
import hmac
import os

from ._keccak import keccak_256
from ._ripemd160 import ripemd160 as _ripemd160_pure


def _require_bytes(name: str, value: bytes) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes.")


def hmac_sha512(key: bytes, message: bytes) -> bytes:
    """Return HMAC-SHA512(key, message)."""
    _require_bytes("key", key)
    _require_bytes("message", message)
    return hmac.new(key, message, hashlib.sha512).digest()


def pbkdf2_hmac_sha512(password: bytes, salt: bytes, iterations: int, dk_length: int) -> bytes:
    """Return PBKDF2-HMAC-SHA512 derived bytes."""
    _require_bytes("password", password)
    _require_bytes("salt", salt)
    if iterations <= 0:
        raise ValueError("iterations must be positive.")
    if dk_length <= 0:
        raise ValueError("dk_length must be positive.")
    return hashlib.pbkdf2_hmac("sha512", password, salt, iterations, dklen=dk_length)


def sha256(data: bytes) -> bytes:
    """Return SHA-256 digest."""
    _require_bytes("data", data)
    return hashlib.sha256(data).digest()


def sha512(data: bytes) -> bytes:
    """Return SHA-512 digest."""
    _require_bytes("data", data)
    return hashlib.sha512(data).digest()


def ripemd160(data: bytes) -> bytes:
    """Return RIPEMD-160 digest.

    Uses OpenSSL through hashlib when available and falls back to the bundled
    pure-Python implementation otherwise.
    """
    _require_bytes("data", data)
    try:
        h = hashlib.new("ripemd160")
    except (ValueError, TypeError):
        return _ripemd160_pure(data)
    h.update(data)
    return h.digest()


def hash160(data: bytes) -> bytes:
    """Return RIPEMD160(SHA256(data))."""
    return ripemd160(sha256(data))


def double_sha256(data: bytes) -> bytes:
    """Return SHA256(SHA256(data))."""
    return sha256(sha256(data))


def keccak256(data: bytes) -> bytes:
    """Return true Keccak-256 digest.

    Ethereum, TRON, and EVM-compatible chains use Keccak-256, not
    hashlib.sha3_256. This function never falls back to SHA3-256.
    """
    _require_bytes("data", data)
    return keccak_256(data)


def secure_random_bytes(n: int) -> bytes:
    """Return cryptographically secure random bytes."""
    if not isinstance(n, int):
        raise TypeError("n must be an integer.")
    if n <= 0:
        raise ValueError("n must be positive.")
    return os.urandom(n)


def bip39_pbkdf2(mnemonic: str, passphrase: str = "") -> bytes:
    """BIP39 PBKDF2-HMAC-SHA512 seed derivation."""
    from .constants import PBKDF2_HMAC_DKLEN, PBKDF2_ITERATIONS

    if not isinstance(mnemonic, str):
        raise TypeError("mnemonic must be a string.")
    if not isinstance(passphrase, str):
        raise TypeError("passphrase must be a string.")

    salt = ("mnemonic" + passphrase).encode("utf-8")
    return pbkdf2_hmac_sha512(
        mnemonic.encode("utf-8"), salt, PBKDF2_ITERATIONS, PBKDF2_HMAC_DKLEN
    )


__all__ = [
    "hmac_sha512",
    "pbkdf2_hmac_sha512",
    "sha256",
    "sha512",
    "ripemd160",
    "hash160",
    "double_sha256",
    "keccak256",
    "secure_random_bytes",
    "bip39_pbkdf2",
]
