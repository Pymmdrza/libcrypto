"""
SHA224 hash algorithm implementation.
"""

import hashlib
from typing import Union, Optional


class SHA224Hash:
    digest_size = 28
    block_size = 64
    oid = "2.16.840.1.101.3.4.2.4"
    
    def __init__(self, data: Optional[bytes] = None):
        self._hasher = hashlib.sha224()
        if data is not None:
            self.update(data)
    
    def update(self, data: Union[bytes, bytearray]) -> None:
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._hasher.update(data)
    
    def digest(self) -> bytes:
        return self._hasher.digest()
    
    def hexdigest(self) -> str:
        return self._hasher.hexdigest()
    
    def copy(self) -> 'SHA224Hash':
        new_hash = SHA224Hash()
        new_hash._hasher = self._hasher.copy()
        return new_hash


def new(data: Optional[bytes] = None) -> SHA224Hash:
    return SHA224Hash(data)


def sha224(data: bytes) -> bytes:
    return hashlib.sha224(data).digest()


digest_size = SHA224Hash.digest_size
block_size = SHA224Hash.block_size 