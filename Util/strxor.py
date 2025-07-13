"""
String XOR operations.

This module provides XOR operations for byte strings.
"""

from typing import Union


def strxor(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte strings.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        XOR result
        
    Raises:
        ValueError: If strings have different lengths
    """
    if len(a) != len(b):
        raise ValueError("XOR arguments must have equal length")
    
    return bytes(x ^ y for x, y in zip(a, b))


def strxor_c(a: bytes, c: int) -> bytes:
    """
    XOR a byte string with a single byte value.
    
    Args:
        a: Byte string
        c: Byte value (0-255)
        
    Returns:
        XOR result
    """
    if not (0 <= c <= 255):
        raise ValueError("c must be a byte value (0-255)")
    
    return bytes(x ^ c for x in a) 