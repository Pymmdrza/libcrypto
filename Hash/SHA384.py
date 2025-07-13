"""
SHA384 hash algorithm implementation.
"""

import hashlib
from typing import Union, Optional


class SHA384Hash:
    digest_size = 48
    block_size = 128
    oid = "2.16.840.1.101.3.4.2.2"
    
    def __init__(self, data: Optional[bytes] = None):
        self._hasher = hashlib.sha384()
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
    
    def copy(self) -> 'SHA384Hash':
        new_hash = SHA384Hash()
        new_hash._hasher = self._hasher.copy()
        return new_hash


def new(data: Optional[bytes] = None) -> SHA384Hash:
    return SHA384Hash(data)


def sha384(data: bytes) -> bytes:
    return hashlib.sha384(data).digest()


digest_size = SHA384Hash.digest_size
block_size = SHA384Hash.block_size 