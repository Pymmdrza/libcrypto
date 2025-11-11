"""
Secp256k1 Elliptic Curve Operations (Pure Python Implementation)

This module provides a robust interface for secp256k1 operations using
pure Python mathematics with the local cryptod library support.

This implementation uses only local cryptographic primitives from the 
cryptod package, eliminating all external dependencies like 'ecdsa'.
"""
from typing import Tuple, Optional
from .constants import (
    SECP256K1_P, SECP256K1_N, SECP256K1_GX, SECP256K1_GY,
    SECP256K1_A, SECP256K1_B, MAX_PRIVATE_KEY
)


class Secp256k1Error(ValueError):
    """Custom exception for secp256k1 related errors."""
    pass


def _mod_inverse(a: int, m: int) -> int:
    """
    Compute modular multiplicative inverse using Extended Euclidean Algorithm.
    
    Args:
        a: The number to find the inverse of
        m: The modulus
        
    Returns:
        The modular inverse of a modulo m
    """
    if a < 0:
        a = (a % m + m) % m
    
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.
    
    Returns:
        Tuple of (gcd, x, y) where gcd = a*x + b*y
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = _extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def _point_add(x1: Optional[int], y1: Optional[int], x2: Optional[int], y2: Optional[int]) -> Tuple[Optional[int], Optional[int]]:
    """
    Add two points on the secp256k1 curve.
    
    Args:
        x1, y1: Coordinates of first point (None represents point at infinity)
        x2, y2: Coordinates of second point (None represents point at infinity)
        
    Returns:
        Tuple of (x3, y3) coordinates of the sum point
    """
    # Handle point at infinity cases
    if x1 is None or y1 is None:
        return x2, y2
    if x2 is None or y2 is None:
        return x1, y1
    
    # Now we know all values are not None
    if x1 == x2:
        if y1 == y2:
            # Point doubling
            s = (3 * x1 * x1 + SECP256K1_A) * _mod_inverse(2 * y1, SECP256K1_P) % SECP256K1_P
        else:
            # Points are inverses (result is point at infinity)
            return None, None
    else:
        # Point addition
        s = (y2 - y1) * _mod_inverse(x2 - x1, SECP256K1_P) % SECP256K1_P
    
    x3 = (s * s - x1 - x2) % SECP256K1_P
    y3 = (s * (x1 - x3) - y1) % SECP256K1_P
    
    return x3, y3


def _point_multiply(k: int, x: int, y: int) -> Tuple[Optional[int], Optional[int]]:
    """
    Multiply a point by a scalar using double-and-add algorithm.
    
    Args:
        k: Scalar multiplier
        x, y: Point coordinates
        
    Returns:
        Tuple of (x, y) coordinates of k*P
    """
    if k == 0:
        return None, None
    if k == 1:
        return x, y
    if k < 0 or k >= SECP256K1_N:
        k = k % SECP256K1_N
    
    # Initialize result as point at infinity
    result_x, result_y = None, None
    addend_x: Optional[int] = x
    addend_y: Optional[int] = y
    
    # Double-and-add algorithm
    while k:
        if k & 1:
            result_x, result_y = _point_add(result_x, result_y, addend_x, addend_y)
        addend_x, addend_y = _point_add(addend_x, addend_y, addend_x, addend_y)
        k >>= 1
    
    return result_x, result_y


def _is_on_curve(x: int, y: int) -> bool:
    """
    Check if a point is on the secp256k1 curve.
    
    Args:
        x, y: Point coordinates
        
    Returns:
        True if the point is on the curve, False otherwise
    """
    return (y * y - x * x * x - SECP256K1_B) % SECP256K1_P == 0


def private_key_to_public_key(private_key: int, compressed: bool = True) -> bytes:
    """
    Derives a public key from a private key integer using pure Python implementation.

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
        # Multiply generator point by private key
        x, y = _point_multiply(private_key, SECP256K1_GX, SECP256K1_GY)
        
        if x is None or y is None:
            raise Secp256k1Error("Invalid public key point generated")
        
        # Verify the point is on the curve
        if not _is_on_curve(x, y):
            raise Secp256k1Error("Generated point is not on the curve")
        
        # Return the public key in the requested format
        if compressed:
            # Compressed format: 0x02/0x03 prefix + x coordinate
            prefix = b'\x02' if y % 2 == 0 else b'\x03'
            return prefix + x.to_bytes(32, 'big')
        else:
            # Uncompressed format: 0x04 prefix + x + y coordinates
            return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
    except Exception as e:
        raise Secp256k1Error(f"Failed to generate public key: {e}") from e


def public_key_to_point_coords(public_key: bytes) -> Tuple[int, int]:
    """
    Converts a public key byte string into its (x, y) integer coordinates.

    Args:
        public_key: The public key as bytes (compressed or uncompressed).

    Returns:
        A tuple containing the (x, y) coordinates as integers.
    """
    try:
        if len(public_key) == 33:
            # Compressed format
            if public_key[0] not in (0x02, 0x03):
                raise Secp256k1Error("Invalid compressed public key prefix")
            
            x = int.from_bytes(public_key[1:33], 'big')
            
            # Compute y from x using curve equation: y² = x³ + 7 (mod p)
            y_squared = (pow(x, 3, SECP256K1_P) + SECP256K1_B) % SECP256K1_P
            y = pow(y_squared, (SECP256K1_P + 1) // 4, SECP256K1_P)
            
            # Choose correct y based on prefix
            if (y % 2 == 0) != (public_key[0] == 0x02):
                y = SECP256K1_P - y
            
        elif len(public_key) == 65:
            # Uncompressed format
            if public_key[0] != 0x04:
                raise Secp256k1Error("Invalid uncompressed public key prefix")
            
            x = int.from_bytes(public_key[1:33], 'big')
            y = int.from_bytes(public_key[33:65], 'big')
        else:
            raise Secp256k1Error(f"Invalid public key length: {len(public_key)}")
        
        # Verify the point is on the curve
        if not _is_on_curve(x, y):
            raise Secp256k1Error("Public key point is not on the curve")
        
        return (x, y)
    except Secp256k1Error:
        raise
    except Exception as e:
        raise Secp256k1Error(f"Failed to extract point from public key: {e}") from e


def decompress_public_key(public_key: bytes) -> bytes:
    """
    Converts a public key to its uncompressed format (65 bytes).

    Args:
        public_key: The public key in either compressed or uncompressed format.

    Returns:
        The 65-byte uncompressed public key.
    """
    try:
        x, y = public_key_to_point_coords(public_key)
        return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
    except Exception as e:
        raise Secp256k1Error(f"Failed to decompress public key: {e}") from e


def compress_public_key(public_key: bytes) -> bytes:
    """
    Converts a public key to its compressed format (33 bytes).

    Args:
        public_key: The public key in either compressed or uncompressed format.

    Returns:
        The 33-byte compressed public key.
    """
    try:
        x, y = public_key_to_point_coords(public_key)
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        return prefix + x.to_bytes(32, 'big')
    except Exception as e:
        raise Secp256k1Error(f"Failed to compress public key: {e}") from e


__all__ = [
    'private_key_to_public_key',
    'public_key_to_point_coords',
    'decompress_public_key',
    'compress_public_key',
    'Secp256k1Error',
]
