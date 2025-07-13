"""
HMAC implementation using Python's hmac module.
"""

import hmac as _hmac
import hashlib
from typing import Union, Optional, Callable


class HMAC:
    """
    HMAC implementation using Python's standard library.
    """
    
    def __init__(self, key: bytes, msg: Optional[bytes] = None, 
                 digestmod: Union[str, Callable] = 'sha256'):
        """
        Initialize HMAC.
        
        Args:
            key: Secret key
            msg: Optional initial message
            digestmod: Hash function to use
        """
        if isinstance(digestmod, str):
            if digestmod == 'sha256':
                digestmod = hashlib.sha256
            elif digestmod == 'sha1':
                digestmod = hashlib.sha1
            elif digestmod == 'sha512':
                digestmod = hashlib.sha512
            elif digestmod == 'md5':
                digestmod = hashlib.md5
            else:
                digestmod = getattr(hashlib, digestmod)
        
        self._hmac = _hmac.new(key, msg, digestmod)
        self.digest_size = self._hmac.digest_size
    
    def update(self, msg: bytes) -> None:
        """Update with new data."""
        self._hmac.update(msg)
    
    def digest(self) -> bytes:
        """Return the digest."""
        return self._hmac.digest()
    
    def hexdigest(self) -> str:
        """Return the hex digest."""
        return self._hmac.hexdigest()
    
    def copy(self) -> 'HMAC':
        """Return a copy."""
        new_hmac = HMAC.__new__(HMAC)
        new_hmac._hmac = self._hmac.copy()
        new_hmac.digest_size = self.digest_size
        return new_hmac


def new(key: bytes, msg: Optional[bytes] = None, 
        digestmod: Union[str, Callable] = 'sha256') -> HMAC:
    """Create a new HMAC object."""
    return HMAC(key, msg, digestmod) 