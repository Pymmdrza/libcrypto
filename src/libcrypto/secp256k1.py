"""Pure Python secp256k1 elliptic-curve operations.

The public API is kept compatible with earlier libcrypto releases while the
private-key-to-public-key path uses Jacobian coordinates and a small fixed-base
lookup table for faster deterministic address derivation.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from .constants import (
    MAX_PRIVATE_KEY,
    SECP256K1_B,
    SECP256K1_GX,
    SECP256K1_GY,
    SECP256K1_N,
    SECP256K1_P,
)

AffinePoint = Tuple[int, int]
JacobianPoint = Tuple[int, int, int]
_INFINITY_JACOBIAN: JacobianPoint = (0, 1, 0)
_G: AffinePoint = (SECP256K1_GX, SECP256K1_GY)
_G_4BIT_TABLE: Optional[List[Optional[AffinePoint]]] = None


class Secp256k1Error(ValueError):
    """Custom exception for secp256k1 related errors."""


def _mod_inverse(a: int, m: int) -> int:
    """Return a modular inverse using Python's constant-time capable pow path."""
    return pow(a % m, -1, m)


def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm kept for backward/internal compatibility."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = _extended_gcd(b % a, a)
    return gcd, y1 - (b // a) * x1, x1


def _is_on_curve(x: int, y: int) -> bool:
    """Return True if (x, y) is a valid secp256k1 affine point."""
    if not (0 <= x < SECP256K1_P and 0 <= y < SECP256K1_P):
        return False
    return (y * y - x * x * x - SECP256K1_B) % SECP256K1_P == 0


def _point_add(
    x1: Optional[int],
    y1: Optional[int],
    x2: Optional[int],
    y2: Optional[int],
) -> Tuple[Optional[int], Optional[int]]:
    """Add two affine points. None/None represents the point at infinity."""
    if x1 is None or y1 is None:
        return x2, y2
    if x2 is None or y2 is None:
        return x1, y1

    if x1 == x2:
        if (y1 + y2) % SECP256K1_P == 0:
            return None, None
        slope = (3 * x1 * x1) * _mod_inverse(2 * y1, SECP256K1_P) % SECP256K1_P
    else:
        slope = (y2 - y1) * _mod_inverse(x2 - x1, SECP256K1_P) % SECP256K1_P

    x3 = (slope * slope - x1 - x2) % SECP256K1_P
    y3 = (slope * (x1 - x3) - y1) % SECP256K1_P
    return x3, y3


def _jacobian_double(point: JacobianPoint) -> JacobianPoint:
    x, y, z = point
    if z == 0 or y == 0:
        return _INFINITY_JACOBIAN

    y2 = (y * y) % SECP256K1_P
    s = (4 * x * y2) % SECP256K1_P
    m = (3 * x * x) % SECP256K1_P
    x3 = (m * m - 2 * s) % SECP256K1_P
    y3 = (m * (s - x3) - 8 * y2 * y2) % SECP256K1_P
    z3 = (2 * y * z) % SECP256K1_P
    return x3, y3, z3


def _jacobian_add_mixed(point: JacobianPoint, affine: AffinePoint) -> JacobianPoint:
    x1, y1, z1 = point
    if z1 == 0:
        return affine[0], affine[1], 1

    x2, y2 = affine
    z1z1 = (z1 * z1) % SECP256K1_P
    u2 = (x2 * z1z1) % SECP256K1_P
    s2 = (y2 * z1 * z1z1) % SECP256K1_P
    h = (u2 - x1) % SECP256K1_P
    r = (2 * (s2 - y1)) % SECP256K1_P

    if h == 0:
        if r == 0:
            return _jacobian_double(point)
        return _INFINITY_JACOBIAN

    hh = (h * h) % SECP256K1_P
    i = (4 * hh) % SECP256K1_P
    j = (h * i) % SECP256K1_P
    v = (x1 * i) % SECP256K1_P
    x3 = (r * r - j - 2 * v) % SECP256K1_P
    y3 = (r * (v - x3) - 2 * y1 * j) % SECP256K1_P
    z3 = ((z1 + h) * (z1 + h) - z1z1 - hh) % SECP256K1_P
    return x3, y3, z3


def _jacobian_to_affine(point: JacobianPoint) -> AffinePoint:
    x, y, z = point
    if z == 0:
        raise Secp256k1Error("Point at infinity cannot be converted to affine coordinates.")
    z_inv = _mod_inverse(z, SECP256K1_P)
    z_inv2 = (z_inv * z_inv) % SECP256K1_P
    z_inv3 = (z_inv2 * z_inv) % SECP256K1_P
    return (x * z_inv2) % SECP256K1_P, (y * z_inv3) % SECP256K1_P


def _build_g_4bit_table() -> List[Optional[AffinePoint]]:
    global _G_4BIT_TABLE
    if _G_4BIT_TABLE is not None:
        return _G_4BIT_TABLE

    table: List[Optional[AffinePoint]] = [None] * 16
    table[1] = _G
    for index in range(2, 16):
        px, py = _point_add(table[index - 1][0], table[index - 1][1], SECP256K1_GX, SECP256K1_GY)  # type: ignore[index]
        if px is None or py is None:
            raise Secp256k1Error("Failed to build secp256k1 fixed-base table.")
        table[index] = (px, py)

    _G_4BIT_TABLE = table
    return table


def _point_multiply(k: int, x: int, y: int) -> Tuple[Optional[int], Optional[int]]:
    """Multiply an arbitrary affine point by scalar k using double-and-add."""
    if k == 0:
        return None, None
    if k < 0 or k >= SECP256K1_N:
        k %= SECP256K1_N
    result_x: Optional[int] = None
    result_y: Optional[int] = None
    addend_x: Optional[int] = x
    addend_y: Optional[int] = y
    while k:
        if k & 1:
            result_x, result_y = _point_add(result_x, result_y, addend_x, addend_y)
        addend_x, addend_y = _point_add(addend_x, addend_y, addend_x, addend_y)
        k >>= 1
    return result_x, result_y


def _scalar_multiply_base(k: int) -> AffinePoint:
    """Fast fixed-base multiplication k*G using a 4-bit window."""
    table = _build_g_4bit_table()
    result = _INFINITY_JACOBIAN
    for char in f"{k:064x}":
        result = _jacobian_double(result)
        result = _jacobian_double(result)
        result = _jacobian_double(result)
        result = _jacobian_double(result)
        value = int(char, 16)
        if value:
            table_point = table[value]
            if table_point is None:
                raise Secp256k1Error("Invalid secp256k1 fixed-base table entry.")
            result = _jacobian_add_mixed(result, table_point)
    return _jacobian_to_affine(result)


def private_key_to_public_key(private_key: int, compressed: bool = True) -> bytes:
    """Derive a secp256k1 public key from a private key integer."""
    if not isinstance(private_key, int):
        raise Secp256k1Error("Private key must be an integer.")
    if not (1 <= private_key <= MAX_PRIVATE_KEY):
        raise Secp256k1Error("Private key is out of the valid range (1 to N-1).")

    try:
        x, y = _scalar_multiply_base(private_key)
        if not _is_on_curve(x, y):
            raise Secp256k1Error("Generated point is not on the curve.")
        if compressed:
            prefix = b"\x02" if y % 2 == 0 else b"\x03"
            return prefix + x.to_bytes(32, "big")
        return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    except Secp256k1Error:
        raise
    except Exception as exc:
        raise Secp256k1Error(f"Failed to generate public key: {exc}") from exc


def public_key_to_point_coords(public_key: bytes) -> Tuple[int, int]:
    """Convert a compressed or uncompressed public key to affine coordinates."""
    if not isinstance(public_key, bytes):
        raise Secp256k1Error("Public key must be bytes.")

    try:
        if len(public_key) == 33:
            if public_key[0] not in (0x02, 0x03):
                raise Secp256k1Error("Invalid compressed public key prefix.")
            x = int.from_bytes(public_key[1:], "big")
            if not (0 <= x < SECP256K1_P):
                raise Secp256k1Error("Invalid public key x-coordinate.")
            y_squared = (pow(x, 3, SECP256K1_P) + SECP256K1_B) % SECP256K1_P
            y = pow(y_squared, (SECP256K1_P + 1) // 4, SECP256K1_P)
            if (y % 2 == 0) != (public_key[0] == 0x02):
                y = SECP256K1_P - y
        elif len(public_key) == 65:
            if public_key[0] != 0x04:
                raise Secp256k1Error("Invalid uncompressed public key prefix.")
            x = int.from_bytes(public_key[1:33], "big")
            y = int.from_bytes(public_key[33:65], "big")
        else:
            raise Secp256k1Error(f"Invalid public key length: {len(public_key)}")

        if not _is_on_curve(x, y):
            raise Secp256k1Error("Public key point is not on the curve.")
        return x, y
    except Secp256k1Error:
        raise
    except Exception as exc:
        raise Secp256k1Error(f"Failed to extract point from public key: {exc}") from exc


def decompress_public_key(public_key: bytes) -> bytes:
    """Return the uncompressed 65-byte form of a public key."""
    x, y = public_key_to_point_coords(public_key)
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def compress_public_key(public_key: bytes) -> bytes:
    """Return the compressed 33-byte form of a public key."""
    x, y = public_key_to_point_coords(public_key)
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + x.to_bytes(32, "big")


__all__ = [
    "private_key_to_public_key",
    "public_key_to_point_coords",
    "decompress_public_key",
    "compress_public_key",
    "Secp256k1Error",
]
