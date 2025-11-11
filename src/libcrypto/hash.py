"""
Internal Cryptographic Hash and KDF Utilities.
This module provides cryptographic hash and KDF functions using the internal
cryptod library (PyCryptodome) when available, with stdlib fallbacks.

The cryptod library provides enhanced cryptographic functions including true Keccak256
for Ethereum support. If cryptod's compiled extensions are not available, the module
falls back to Python's standard library implementations.
"""

import sys
import os as _os
import hashlib
import hmac

# Try to use internal cryptod library if compiled extensions are available
_CRYPTOD_AVAILABLE = False
try:
    _cryptod_lib_path = _os.path.join(_os.path.dirname(__file__), "cryptod", "lib")
    if _cryptod_lib_path not in sys.path:
        sys.path.insert(0, _cryptod_lib_path)

    # Import from internal cryptod library
    from libcrypto.cryptod.Crypto.Hash import (
        SHA256,
        SHA512,
        HMAC as CRYPTOD_HMAC,
        RIPEMD160,
        keccak,
    )
    from libcrypto.cryptod.Crypto.Protocol import KDF as CRYPTOD_KDF
    from libcrypto.cryptod.Crypto import get_random_bytes as cryptod_random_bytes

    _CRYPTOD_AVAILABLE = True
except (ImportError, OSError, TypeError, AttributeError) as e:
    # Cryptod not available (missing compiled extensions or Python version incompatibility), use stdlib
    _CRYPTOD_AVAILABLE = False


def hmac_sha512(key: bytes, message: bytes) -> bytes:
    """
    Compute HMAC-SHA512 using cryptod library if available, otherwise stdlib.

    Args:
        key: Secret key bytes.
        message: Message bytes to authenticate.

    Returns:
        HMAC-SHA512 digest bytes (64 bytes).
    """
    if _CRYPTOD_AVAILABLE:
        h = CRYPTOD_HMAC.new(key, digestmod=SHA512)
        h.update(message)
        return h.digest()
    else:
        return hmac.new(key, message, hashlib.sha512).digest()


def pbkdf2_hmac_sha512(
    password: bytes, salt: bytes, iterations: int, dk_length: int
) -> bytes:
    """
    PBKDF2 key derivation using HMAC-SHA512 with cryptod library if available, otherwise stdlib.

    Args:
        password: Password bytes.
        salt: Salt bytes.
        iterations: Number of iterations.
        dk_length: Desired key length in bytes.

    Returns:
        Derived key bytes of specified length.
    """
    if _CRYPTOD_AVAILABLE:
        return CRYPTOD_KDF.PBKDF2(
            password, salt, dkLen=dk_length, count=iterations, hmac_hash_module=SHA512
        )
    else:
        return hashlib.pbkdf2_hmac(
            "sha512", password, salt, iterations, dklen=dk_length
        )


def sha256(data: bytes) -> bytes:
    """
    Compute SHA256 hash using cryptod library if available, otherwise stdlib.
    """
    if _CRYPTOD_AVAILABLE:
        h = SHA256.new(data)
        return h.digest()
    else:
        return hashlib.sha256(data).digest()


def ripemd160(data: bytes) -> bytes:
    """
    Compute RIPEMD160 hash using cryptod library if available, otherwise stdlib.
    """
    if _CRYPTOD_AVAILABLE:
        h = RIPEMD160.new(data)
        return h.digest()
    else:
        try:
            return hashlib.new("ripemd160", data).digest()
        except ValueError:
            # RIPEMD160 not available in stdlib on this platform
            raise NotImplementedError(
                "RIPEMD160 is not available on this system. "
                "The cryptod library requires compiled extensions. "
                "Please install pycryptodome: pip install pycryptodome"
            )


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
    Compute Keccak-256 hash (used in Ethereum).

    Uses cryptod library for true Keccak256 if available (different from SHA3-256).
    Keccak256 is the original Keccak before it became SHA3, and Ethereum uses this version.

    Falls back to SHA3-256 if cryptod is not available (note: this produces different hashes).
    """
    if _CRYPTOD_AVAILABLE:
        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    else:
        return hashlib.sha3_256(data).digest()


def secure_random_bytes(n: int) -> bytes:
    """
    Generate cryptographically secure random bytes using cryptod library if available, otherwise os.urandom.

    Args:
        n: Number of bytes to generate.

    Returns:
        Random bytes of length n.
    """
    if _CRYPTOD_AVAILABLE:
        return cryptod_random_bytes(n)
    else:
        return _os.urandom(n)


def bip39_pbkdf2(mnemonic: str, passphrase: str = "") -> bytes:
    """
    BIP39-specific PBKDF2 for converting mnemonic to seed.
    """
    from .constants import PBKDF2_ITERATIONS, PBKDF2_HMAC_DKLEN

    salt = ("mnemonic" + passphrase).encode("utf-8")
    return pbkdf2_hmac_sha512(
        mnemonic.encode("utf-8"), salt, PBKDF2_ITERATIONS, PBKDF2_HMAC_DKLEN
    )
