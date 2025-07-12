"""
Type stubs for Core._hash_core C extension module.

This module provides specialized hash functions implemented in C for performance.
"""

from typing import Union, Optional

# Type aliases
BytesLike = Union[bytes, bytearray, memoryview]

# Keccak hash functions
def keccak_224(data: BytesLike) -> bytes:
    """Compute Keccak-224 hash."""
    ...

def keccak_256(data: BytesLike) -> bytes:
    """Compute Keccak-256 hash (used by Ethereum)."""
    ...

def keccak_384(data: BytesLike) -> bytes:
    """Compute Keccak-384 hash."""
    ...

def keccak_512(data: BytesLike) -> bytes:
    """Compute Keccak-512 hash."""
    ...

# SHA-3 hash functions (standardized Keccak)
def sha3_224(data: BytesLike) -> bytes:
    """Compute SHA3-224 hash."""
    ...

def sha3_256(data: BytesLike) -> bytes:
    """Compute SHA3-256 hash."""
    ...

def sha3_384(data: BytesLike) -> bytes:
    """Compute SHA3-384 hash."""
    ...

def sha3_512(data: BytesLike) -> bytes:
    """Compute SHA3-512 hash."""
    ...

# SHAKE extendable output functions
def shake_128(data: BytesLike, output_length: int) -> bytes:
    """Compute SHAKE-128 with specified output length."""
    ...

def shake_256(data: BytesLike, output_length: int) -> bytes:
    """Compute SHAKE-256 with specified output length."""
    ...

# BLAKE2b hash functions
def blake2b(data: BytesLike, digest_size: int = 64, key: Optional[BytesLike] = None, 
           salt: Optional[BytesLike] = None, person: Optional[BytesLike] = None) -> bytes:
    """Compute BLAKE2b hash with optional parameters."""
    ...

def blake2b_224(data: BytesLike, key: Optional[BytesLike] = None) -> bytes:
    """Compute BLAKE2b with 224-bit output."""
    ...

def blake2b_256(data: BytesLike, key: Optional[BytesLike] = None) -> bytes:
    """Compute BLAKE2b with 256-bit output."""
    ...

def blake2b_384(data: BytesLike, key: Optional[BytesLike] = None) -> bytes:
    """Compute BLAKE2b with 384-bit output."""
    ...

def blake2b_512(data: BytesLike, key: Optional[BytesLike] = None) -> bytes:
    """Compute BLAKE2b with 512-bit output."""
    ...

# BLAKE2s hash functions
def blake2s(data: BytesLike, digest_size: int = 32, key: Optional[BytesLike] = None,
           salt: Optional[BytesLike] = None, person: Optional[BytesLike] = None) -> bytes:
    """Compute BLAKE2s hash with optional parameters."""
    ...

def blake2s_128(data: BytesLike, key: Optional[BytesLike] = None) -> bytes:
    """Compute BLAKE2s with 128-bit output."""
    ...

def blake2s_160(data: BytesLike, key: Optional[BytesLike] = None) -> bytes:
    """Compute BLAKE2s with 160-bit output."""
    ...

def blake2s_224(data: BytesLike, key: Optional[BytesLike] = None) -> bytes:
    """Compute BLAKE2s with 224-bit output."""
    ...

def blake2s_256(data: BytesLike, key: Optional[BytesLike] = None) -> bytes:
    """Compute BLAKE2s with 256-bit output."""
    ...

# GHASH functions for GCM mode
def ghash(h: BytesLike, a: BytesLike, c: BytesLike) -> bytes:
    """Compute GHASH function for GCM authentication."""
    ...

def ghash_portable(h: BytesLike, a: BytesLike, c: BytesLike) -> bytes:
    """Portable implementation of GHASH function."""
    ...

def ghash_clmul(h: BytesLike, a: BytesLike, c: BytesLike) -> bytes:
    """CLMUL-optimized implementation of GHASH function."""
    ...

# SipHash functions
def siphash_64(key: BytesLike, data: BytesLike) -> bytes:
    """Compute SipHash-2-4 producing 64-bit output."""
    ...

def siphash_128(key: BytesLike, data: BytesLike) -> bytes:
    """Compute SipHash-2-4 producing 128-bit output."""
    ...

# cSHAKE customizable SHAKE functions
def cshake_128(data: BytesLike, output_length: int, name: BytesLike = b"", 
               custom: BytesLike = b"") -> bytes:
    """Compute cSHAKE-128 with customization parameters."""
    ...

def cshake_256(data: BytesLike, output_length: int, name: BytesLike = b"",
               custom: BytesLike = b"") -> bytes:
    """Compute cSHAKE-256 with customization parameters."""
    ...

# KMAC message authentication codes
def kmac_128(key: BytesLike, data: BytesLike, output_length: int,
             custom: BytesLike = b"") -> bytes:
    """Compute KMAC-128 message authentication code."""
    ...

def kmac_256(key: BytesLike, data: BytesLike, output_length: int,
             custom: BytesLike = b"") -> bytes:
    """Compute KMAC-256 message authentication code."""
    ...

# TupleHash functions
def tuple_hash_128(tuple_data: list, output_length: int, custom: BytesLike = b"") -> bytes:
    """Compute TupleHash-128 over a tuple of byte strings."""
    ...

def tuple_hash_256(tuple_data: list, output_length: int, custom: BytesLike = b"") -> bytes:
    """Compute TupleHash-256 over a tuple of byte strings."""
    ...

# Kangaroo Twelve hash function
def kangaroo_twelve(data: BytesLike, output_length: int = 32, custom: BytesLike = b"") -> bytes:
    """Compute KangarooTwelve hash function."""
    ...

# TurboSHAKE functions
def turbo_shake_128(data: BytesLike, output_length: int, domain_separation: int = 0x1F) -> bytes:
    """Compute TurboSHAKE128 with specified domain separation."""
    ...

def turbo_shake_256(data: BytesLike, output_length: int, domain_separation: int = 0x1F) -> bytes:
    """Compute TurboSHAKE256 with specified domain separation."""
    ... 