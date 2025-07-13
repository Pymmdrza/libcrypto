"""
Keccak hash implementation using hashlib's SHA3.
"""

import hashlib
from typing import Optional


def keccak_hash(data: bytes, digest_bits: int = 256) -> bytes:
    """
    Compute Keccak hash using SHA3.
    
    Args:
        data: Data to hash
        digest_bits: Output size in bits (256, 384, 512)
    
    Returns:
        Hash digest
    """
    if digest_bits == 256:
        return hashlib.sha3_256(data).digest()
    elif digest_bits == 384:
        return hashlib.sha3_384(data).digest()
    elif digest_bits == 512:
        return hashlib.sha3_512(data).digest()
    else:
        raise ValueError(f"Unsupported digest size: {digest_bits}")


class KeccakHash:
    """Simple Keccak wrapper."""
    
    def __init__(self, digest_bits: int = 256):
        self.digest_bits = digest_bits
        self.digest_size = digest_bits // 8
        self._data = b''
    
    def update(self, data: bytes) -> None:
        self._data += data
    
    def digest(self) -> bytes:
        return keccak_hash(self._data, self.digest_bits)
    
    def hexdigest(self) -> str:
        return self.digest().hex()


def new(digest_bits: int = 256) -> KeccakHash:
    return KeccakHash(digest_bits) 