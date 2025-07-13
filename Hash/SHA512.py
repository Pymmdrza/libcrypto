"""
SHA512 hash algorithm implementation.

This module provides SHA512 hashing functionality using Python's hashlib
as a replacement for the original C implementation.
"""

import hashlib
from typing import Union, Optional


class SHA512Hash:
    """
    A SHA512 hasher object.
    
    This class provides the same interface as the original libcrypto SHA512
    but uses Python's hashlib implementation instead of C extensions.
    """
    
    digest_size = 64
    block_size = 128
    oid = "2.16.840.1.101.3.4.2.3"  # SHA512 OID
    
    def __init__(self, data: Optional[bytes] = None):
        """
        Initialize a new SHA512 hash object.
        
        Args:
            data: Optional initial data to hash.
        """
        self._hasher = hashlib.sha512()
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
    
    def copy(self) -> 'SHA512Hash':
        """
        Return a copy of the hash object.
        
        Returns:
            A new SHA512Hash object with the same state.
        """
        new_hash = SHA512Hash()
        new_hash._hasher = self._hasher.copy()
        return new_hash


# Factory function for compatibility
def new(data: Optional[bytes] = None) -> SHA512Hash:
    """
    Create a new SHA512 hash object.
    
    Args:
        data: Optional initial data to hash.
        
    Returns:
        A new SHA512Hash object.
    """
    return SHA512Hash(data)


# Convenience function
def sha512(data: bytes) -> bytes:
    """
    Compute SHA512 hash of data in one call.
    
    Args:
        data: The data to hash.
        
    Returns:
        The SHA512 hash digest.
    """
    return hashlib.sha512(data).digest()


# Module-level constants
digest_size = SHA512Hash.digest_size
block_size = SHA512Hash.block_size 