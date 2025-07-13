"""
SHA3-256 hash implementation.
"""

import hashlib
from typing import Union, Optional


class SHA3_256Hash:
    digest_size = 32
    block_size = 136
    
    def __init__(self, data: Optional[bytes] = None):
        self._hasher = hashlib.sha3_256()
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
    
    def copy(self) -> 'SHA3_256Hash':
        new_hash = SHA3_256Hash()
        new_hash._hasher = self._hasher.copy()
        return new_hash


def new(data: Optional[bytes] = None) -> SHA3_256Hash:
    return SHA3_256Hash(data)


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


digest_size = SHA3_256Hash.digest_size
block_size = SHA3_256Hash.block_size 