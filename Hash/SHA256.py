"""
SHA256 hash algorithm implementation.

This module provides SHA256 hashing functionality using Python's hashlib
as a replacement for the original C implementation.
"""

import hashlib
from typing import Union, Optional


class SHA256Hash:
    """
    A SHA256 hasher object.
    
    This class provides the same interface as the original libcrypto SHA256
    but uses Python's hashlib implementation instead of C extensions.
    """
    
    digest_size = 32
    block_size = 64
    oid = "2.16.840.1.101.3.4.2.1"  # SHA256 OID
    
    def __init__(self, data: Optional[bytes] = None):
        """
        Initialize a new SHA256 hash object.
        
        Args:
            data: Optional initial data to hash.
        """
        self._hasher = hashlib.sha256()
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
    
    def copy(self) -> 'SHA256Hash':
        """
        Return a copy of the hash object.
        
        Returns:
            A new SHA256Hash object with the same state.
        """
        new_hash = SHA256Hash()
        new_hash._hasher = self._hasher.copy()
        return new_hash


# Factory function for compatibility
def new(data: Optional[bytes] = None) -> SHA256Hash:
    """
    Create a new SHA256 hash object.
    
    Args:
        data: Optional initial data to hash.
        
    Returns:
        A new SHA256Hash object.
    """
    return SHA256Hash(data)


# Convenience function
def sha256(data: bytes) -> bytes:
    """
    Compute SHA256 hash of data in one call.
    
    Args:
        data: The data to hash.
        
    Returns:
        The SHA256 hash digest.
    """
    return hashlib.sha256(data).digest()


# Module-level constants
digest_size = SHA256Hash.digest_size
block_size = SHA256Hash.block_size 