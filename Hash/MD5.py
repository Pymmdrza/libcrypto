"""
MD5 hash algorithm implementation.

This module provides MD5 hashing functionality using Python's hashlib
as a replacement for the original C implementation.
"""

import hashlib
from typing import Union, Optional


class MD5Hash:
    """
    A MD5 hasher object.
    
    This class provides the same interface as the original libcrypto MD5
    but uses Python's hashlib implementation instead of C extensions.
    """
    
    digest_size = 16
    block_size = 64
    oid = "1.2.840.113549.2.5"  # MD5 OID
    
    def __init__(self, data: Optional[bytes] = None):
        """
        Initialize a new MD5 hash object.
        
        Args:
            data: Optional initial data to hash.
        """
        self._hasher = hashlib.md5()
        if data is not None:
            self.update(data)
    
    def update(self, data: Union[bytes, bytearray]) -> None:
        """
        Update the hash object with new data.
        
        Args:
            data: The data to hash.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._hasher.update(data)
    
    def digest(self) -> bytes:
        """
        Return the digest of the data.
        
        Returns:
            The hash digest as bytes.
        """
        return self._hasher.digest()
    
    def hexdigest(self) -> str:
        """
        Return the digest of the data as a hex string.
        
        Returns:
            The hash digest as a hexadecimal string.
        """
        return self._hasher.hexdigest()
    
    def copy(self) -> 'MD5Hash':
        """
        Return a copy of the hash object.
        
        Returns:
            A new MD5Hash object with the same state.
        """
        new_hash = MD5Hash()
        new_hash._hasher = self._hasher.copy()
        return new_hash


# Factory function for compatibility
def new(data: Optional[bytes] = None) -> MD5Hash:
    """
    Create a new MD5 hash object.
    
    Args:
        data: Optional initial data to hash.
        
    Returns:
        A new MD5Hash object.
    """
    return MD5Hash(data)


# Convenience function
def md5(data: bytes) -> bytes:
    """
    Compute MD5 hash of data in one call.
    
    Args:
        data: The data to hash.
        
    Returns:
        The MD5 hash digest.
    """
    return hashlib.md5(data).digest()


# Module-level constants
digest_size = MD5Hash.digest_size
block_size = MD5Hash.block_size 