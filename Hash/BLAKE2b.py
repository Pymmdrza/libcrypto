"""
BLAKE2b hash implementation.
"""

import hashlib
from typing import Union, Optional


class BLAKE2bHash:
    def __init__(self, digest_size: int = 64, key: Optional[bytes] = None, 
                 data: Optional[bytes] = None):
        self.digest_size = digest_size
        self._hasher = hashlib.blake2b(digest_size=digest_size, key=key)
        if data:
            self.update(data)
    
    def update(self, data: Union[bytes, bytearray]) -> None:
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._hasher.update(data)
    
    def digest(self) -> bytes:
        return self._hasher.digest()
    
    def hexdigest(self) -> str:
        return self._hasher.hexdigest()
    
    def copy(self) -> 'BLAKE2bHash':
        new_hash = BLAKE2bHash.__new__(BLAKE2bHash)
        new_hash.digest_size = self.digest_size
        new_hash._hasher = self._hasher.copy()
        return new_hash


def new(digest_size: int = 64, key: Optional[bytes] = None, 
        data: Optional[bytes] = None) -> BLAKE2bHash:
    return BLAKE2bHash(digest_size, key, data) 