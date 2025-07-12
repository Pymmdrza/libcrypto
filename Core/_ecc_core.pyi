"""
Type stubs for Core._ecc_core C extension module.

This module provides elliptic curve cryptography functions implemented in C for performance.
"""

from typing import Tuple, Union, Optional

# Type aliases
BytesLike = Union[bytes, bytearray, memoryview]
Point = Tuple[int, int]  # (x, y) coordinates
ECCPoint = Tuple[int, int, int]  # Projective coordinates (X, Y, Z)

# secp256k1 elliptic curve functions
def secp256k1_point_add(p1: Point, p2: Point) -> Point:
    """Add two points on the secp256k1 curve."""
    ...

def secp256k1_point_double(point: Point) -> Point:
    """Double a point on the secp256k1 curve."""
    ...

def secp256k1_point_multiply(scalar: int, point: Point) -> Point:
    """Multiply a point by a scalar on the secp256k1 curve."""
    ...

def secp256k1_point_from_bytes(data: BytesLike, compressed: bool = True) -> Point:
    """Decode a point from byte representation."""
    ...

def secp256k1_point_to_bytes(point: Point, compressed: bool = True) -> bytes:
    """Encode a point to byte representation."""
    ...

def secp256k1_private_key_to_public_key(private_key: BytesLike, compressed: bool = True) -> bytes:
    """Derive public key from private key."""
    ...

def secp256k1_sign(private_key: BytesLike, message_hash: BytesLike) -> Tuple[int, int]:
    """Sign a message hash with ECDSA."""
    ...

def secp256k1_verify(public_key: BytesLike, message_hash: BytesLike, signature: Tuple[int, int]) -> bool:
    """Verify an ECDSA signature."""
    ...

def secp256k1_recover_public_key(message_hash: BytesLike, signature: Tuple[int, int], recovery_id: int) -> bytes:
    """Recover public key from signature and message hash."""
    ...

# P-256 (secp256r1) curve functions
def p256_point_add(p1: Point, p2: Point) -> Point:
    """Add two points on the P-256 curve."""
    ...

def p256_point_double(point: Point) -> Point:
    """Double a point on the P-256 curve."""
    ...

def p256_point_multiply(scalar: int, point: Point) -> Point:
    """Multiply a point by a scalar on the P-256 curve."""
    ...

def p256_private_key_to_public_key(private_key: BytesLike, compressed: bool = True) -> bytes:
    """Derive public key from private key on P-256."""
    ...

# P-384 (secp384r1) curve functions
def p384_point_add(p1: Point, p2: Point) -> Point:
    """Add two points on the P-384 curve."""
    ...

def p384_point_double(point: Point) -> Point:
    """Double a point on the P-384 curve."""
    ...

def p384_point_multiply(scalar: int, point: Point) -> Point:
    """Multiply a point by a scalar on the P-384 curve."""
    ...

def p384_private_key_to_public_key(private_key: BytesLike, compressed: bool = True) -> bytes:
    """Derive public key from private key on P-384."""
    ...

# P-521 (secp521r1) curve functions
def p521_point_add(p1: Point, p2: Point) -> Point:
    """Add two points on the P-521 curve."""
    ...

def p521_point_double(point: Point) -> Point:
    """Double a point on the P-521 curve."""
    ...

def p521_point_multiply(scalar: int, point: Point) -> Point:
    """Multiply a point by a scalar on the P-521 curve."""
    ...

def p521_private_key_to_public_key(private_key: BytesLike, compressed: bool = True) -> bytes:
    """Derive public key from private key on P-521."""
    ...

# Curve25519 functions
def curve25519_scalar_multiply(scalar: BytesLike, point: BytesLike) -> bytes:
    """Perform scalar multiplication on Curve25519."""
    ...

def curve25519_base_point_multiply(scalar: BytesLike) -> bytes:
    """Multiply the base point by a scalar on Curve25519."""
    ...

def curve25519_generate_public_key(private_key: BytesLike) -> bytes:
    """Generate public key from private key on Curve25519."""
    ...

# Ed25519 signature functions
def ed25519_sign(private_key: BytesLike, message: BytesLike) -> bytes:
    """Sign a message using Ed25519."""
    ...

def ed25519_verify(public_key: BytesLike, message: BytesLike, signature: BytesLike) -> bool:
    """Verify an Ed25519 signature."""
    ...

def ed25519_public_key_from_private(private_key: BytesLike) -> bytes:
    """Derive Ed25519 public key from private key."""
    ...

# Curve448 functions
def curve448_scalar_multiply(scalar: BytesLike, point: BytesLike) -> bytes:
    """Perform scalar multiplication on Curve448."""
    ...

def curve448_base_point_multiply(scalar: BytesLike) -> bytes:
    """Multiply the base point by a scalar on Curve448."""
    ...

def curve448_generate_public_key(private_key: BytesLike) -> bytes:
    """Generate public key from private key on Curve448."""
    ...

# Ed448 signature functions
def ed448_sign(private_key: BytesLike, message: BytesLike, context: BytesLike = b"") -> bytes:
    """Sign a message using Ed448."""
    ...

def ed448_verify(public_key: BytesLike, message: BytesLike, signature: BytesLike, context: BytesLike = b"") -> bool:
    """Verify an Ed448 signature."""
    ...

def ed448_public_key_from_private(private_key: BytesLike) -> bytes:
    """Derive Ed448 public key from private key."""
    ...

# Montgomery ladder operations
def montgomery_ladder(scalar: BytesLike, point: BytesLike, curve_params: Tuple[int, int, int]) -> bytes:
    """Perform Montgomery ladder scalar multiplication."""
    ...

# Modular arithmetic for curve operations
def mod25519_reduce(input_bytes: BytesLike) -> bytes:
    """Reduce a value modulo 2^255 - 19."""
    ...

def mod25519_multiply(a: BytesLike, b: BytesLike) -> bytes:
    """Multiply two values modulo 2^255 - 19."""
    ...

def mod25519_square(a: BytesLike) -> bytes:
    """Square a value modulo 2^255 - 19."""
    ...

def mod25519_invert(a: BytesLike) -> bytes:
    """Compute modular inverse modulo 2^255 - 19."""
    ... 