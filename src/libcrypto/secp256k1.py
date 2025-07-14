"""
Secp256k1 Elliptic Curve Operations (using the 'ecdsa' library)

This module provides a robust interface for secp256k1 operations by
wrapping the 'ecdsa' library, which is a highly stable and focused package
for Elliptic Curve Digital Signature Algorithm.

This implementation replaces the pycryptodome backend to avoid environment
and installation issues.
"""
from typing import Tuple
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import sigencode_string, sigdecode_string
from .constants import MAX_PRIVATE_KEY


class Secp256k1Error(ValueError):
    """Custom exception for secp256k1 related errors."""
    pass


def private_key_to_public_key(private_key: int, compressed: bool = True) -> bytes:
    """
    Derives a public key from a private key integer using the 'ecdsa' library.

    Args:
        private_key: The private key as an integer.
        compressed: If True, returns a 33-byte compressed public key.
                    If False, returns a 65-byte uncompressed public key.

    Returns:
        The public key as a byte string.

    Raises:
        Secp256k1Error: If the private key is out of the valid range.
    """
    if not (1 <= private_key <= MAX_PRIVATE_KEY):
        raise Secp256k1Error("Private key is out of the valid range (1 to N-1).")

    try:
        # Create a SigningKey object from the private key bytes.
        private_key_bytes = private_key.to_bytes(32, 'big')
        sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)

        # Get the corresponding VerifyingKey (public key).
        vk = sk.verifying_key

        # Return the public key in the requested format.
        if compressed:
            return vk.to_string("compressed")
        else:
            return vk.to_string("uncompressed")
    except Exception as e:
        raise Secp256k1Error(f"Failed to generate public key with ecdsa: {e}") from e


def public_key_to_point_coords(public_key: bytes) -> Tuple[int, int]:
    """
    Converts a public key byte string into its (x, y) integer coordinates.

    Args:
        public_key: The public key as bytes (compressed or uncompressed).

    Returns:
        A tuple containing the (x, y) coordinates as integers.
    """
    try:
        vk = VerifyingKey.from_string(public_key, curve=SECP256k1)
        # The public_point attribute holds the x and y coordinates.
        return (vk.pubkey.point.x(), vk.pubkey.point.y())
    except Exception as e:
        raise Secp256k1Error(f"Failed to extract point from public key: {e}") from e


def decompress_public_key(public_key: bytes) -> bytes:
    """
    Converts a public key to its uncompressed format (65 bytes) using 'ecdsa'.

    Args:
        public_key: The public key in either compressed or uncompressed format.

    Returns:
        The 65-byte uncompressed public key.
    """
    try:
        # Create a VerifyingKey from the input bytes. It handles both formats.
        vk = VerifyingKey.from_string(public_key, curve=SECP256k1)
        return vk.to_string("uncompressed")
    except Exception as e:
        raise Secp256k1Error(f"Failed to decompress public key: {e}") from e


def compress_public_key(public_key: bytes) -> bytes:
    """
    Converts a public key to its compressed format (33 bytes) using 'ecdsa'.

    Args:
        public_key: The public key in either compressed or uncompressed format.

    Returns:
        The 33-byte compressed public key.
    """
    try:
        # Create a VerifyingKey from the input bytes.
        vk = VerifyingKey.from_string(public_key, curve=SECP256k1)
        return vk.to_string("compressed")
    except Exception as e:
        raise Secp256k1Error(f"Failed to compress public key: {e}") from e


__all__ = [
    'private_key_to_public_key',
    'public_key_to_point_coords',
    'decompress_public_key',
    'compress_public_key',
    'Secp256k1Error',
]
