"""
Cryptographically secure random number generation.

This module provides random number generation functions using Python's secrets module.
"""

import secrets
from typing import Union


def get_random_bytes(length: int) -> bytes:
    """
    Generate random bytes.
    
    Args:
        length: Number of bytes to generate
        
    Returns:
        Random bytes
    """
    return secrets.token_bytes(length)


def random_int(min_val: int = 0, max_val: int = 2**32 - 1) -> int:
    """
    Generate a random integer in the specified range.
    
    Args:
        min_val: Minimum value (inclusive)
        max_val: Maximum value (inclusive)
        
    Returns:
        Random integer
    """
    return secrets.randbelow(max_val - min_val + 1) + min_val


class StrongRandom:
    """
    Strong random number generator.
    
    This class provides a cryptographically secure random number generator
    using Python's secrets module.
    """
    
    @staticmethod
    def read(length: int) -> bytes:
        """
        Read random bytes.
        
        Args:
            length: Number of bytes to read
            
        Returns:
            Random bytes
        """
        return get_random_bytes(length)
    
    @staticmethod
    def randint(min_val: int, max_val: int) -> int:
        """
        Generate random integer.
        
        Args:
            min_val: Minimum value (inclusive)
            max_val: Maximum value (inclusive)
            
        Returns:
            Random integer
        """
        return random_int(min_val, max_val)


# Default instance
new = StrongRandom 