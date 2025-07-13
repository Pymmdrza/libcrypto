"""
SHA3-512 hash implementation.
"""

import hashlib
from typing import Union, Optional


class SHA3_512Hash:
    digest_size = 64
    block_size = 72
    
    def __init__(self, data: Optional[bytes] = None):
        self._hasher = hashlib.sha3_512()
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
    
    def copy(self) -> 'SHA3_512Hash':
        new_hash = SHA3_512Hash()
        new_hash._hasher = self._hasher.copy()
        return new_hash


def new(data: Optional[bytes] = None) -> SHA3_512Hash:
    return SHA3_512Hash(data)


def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


digest_size = SHA3_512Hash.digest_size
block_size = SHA3_512Hash.block_size 