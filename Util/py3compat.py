"""
Python 3 compatibility utilities.

This module provides compatibility functions for working with bytes and strings.
"""

import sys
from typing import Union, Any


def bchr(s: int) -> bytes:
    """
    Convert an integer to a single byte.
    
    Args:
        s: Integer (0-255)
        
    Returns:
        Single byte
    """
    return bytes([s])


def bord(s: Union[bytes, int]) -> int:
    """
    Convert a byte to an integer.
    
    Args:
        s: Byte or integer
        
    Returns:
        Integer value
    """
    if isinstance(s, int):
        return s
    return s[0] if isinstance(s, (bytes, bytearray)) else ord(s)


def tobytes(s: Union[str, bytes], encoding: str = 'latin-1') -> bytes:
    """
    Convert string to bytes.
    
    Args:
        s: String or bytes
        encoding: Encoding to use
        
    Returns:
        Bytes object
    """
    if isinstance(s, str):
        return s.encode(encoding)
    return s


def tostr(s: Union[str, bytes], encoding: str = 'latin-1') -> str:
    """
    Convert bytes to string.
    
    Args:
        s: String or bytes
        encoding: Encoding to use
        
    Returns:
        String object
    """
    if isinstance(s, bytes):
        return s.decode(encoding)
    return s


def is_string(s: Any) -> bool:
    """
    Check if object is a string.
    
    Args:
        s: Object to check
        
    Returns:
        True if string, False otherwise
    """
    return isinstance(s, str)


def is_bytes(s: Any) -> bool:
    """
    Check if object is bytes.
    
    Args:
        s: Object to check
        
    Returns:
        True if bytes, False otherwise
    """
    return isinstance(s, (bytes, bytearray))


# For compatibility
byte_string = bytes 