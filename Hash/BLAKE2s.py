"""
BLAKE2s hash implementation.
"""

import hashlib
from typing import Union, Optional


class BLAKE2sHash:
    def __init__(self, digest_size: int = 32, key: Optional[bytes] = None, 
                 data: Optional[bytes] = None):
        self.digest_size = digest_size
        self._hasher = hashlib.blake2s(digest_size=digest_size, key=key)
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
    
    def copy(self) -> 'BLAKE2sHash':
        new_hash = BLAKE2sHash.__new__(BLAKE2sHash)
        new_hash.digest_size = self.digest_size
        new_hash._hasher = self._hasher.copy()
        return new_hash


def new(digest_size: int = 32, key: Optional[bytes] = None, 
        data: Optional[bytes] = None) -> BLAKE2sHash:
    return BLAKE2sHash(digest_size, key, data) 