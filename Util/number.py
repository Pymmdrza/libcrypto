"""
Number theory utility functions.

This module provides number theory utilities adapted from pycryptodome.
"""

import math
import struct
import secrets
from typing import Union


def bytes_to_long(s: bytes) -> int:
    """
    Convert a byte string to a long integer.
    
    Args:
        s: Byte string to convert
        
    Returns:
        Integer representation
    """
    return int.from_bytes(s, byteorder='big')


def long_to_bytes(n: int, blocksize: int = 0) -> bytes:
    """
    Convert a long integer to a byte string.
    
    Args:
        n: Integer to convert
        blocksize: Minimum size of output
        
    Returns:
        Byte string representation
    """
    if n == 0:
        s = b'\x00'
    else:
        # Calculate the number of bytes needed
        byte_length = (n.bit_length() + 7) // 8
        s = n.to_bytes(byte_length, byteorder='big')
    
    # Pad if necessary
    if blocksize > 0 and len(s) < blocksize:
        s = b'\x00' * (blocksize - len(s)) + s
    
    return s


def size(n: int) -> int:
    """
    Return the size of a number in bits.
    
    Args:
        n: Number to measure
        
    Returns:
        Number of bits
    """
    if n == 0:
        return 0
    return n.bit_length()


def GCD(a: int, b: int) -> int:
    """
    Greatest Common Divisor using Euclidean algorithm.
    
    Args:
        a: First number
        b: Second number
        
    Returns:
        GCD of a and b
    """
    return math.gcd(a, b)


def inverse(a: int, m: int) -> int:
    """
    Modular multiplicative inverse.
    
    Args:
        a: Number to find inverse of
        m: Modulus
        
    Returns:
        Modular inverse of a modulo m
    """
    return pow(a, -1, m)


def isPrime(n: int, k: int = 25) -> bool:
    """
    Miller-Rabin primality test.
    
    Args:
        n: Number to test
        k: Number of rounds
        
    Returns:
        True if probably prime, False if composite
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as d * 2^r
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Miller-Rabin test
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def getPrime(N: int) -> int:
    """
    Generate a random prime number with N bits.
    
    Args:
        N: Number of bits
        
    Returns:
        Random prime number
    """
    if N < 2:
        raise ValueError("N must be at least 2")
    
    # Generate random odd number with N bits
    while True:
        # Generate random number with exactly N bits
        n = secrets.randbits(N)
        # Ensure it has exactly N bits
        n |= (1 << (N - 1))  # Set MSB
        n |= 1  # Set LSB (make odd)
        
        if isPrime(n):
            return n


def getRandomInteger(N: int) -> int:
    """
    Generate a random integer with exactly N bits.
    
    Args:
        N: Number of bits
        
    Returns:
        Random integer
    """
    if N <= 0:
        return 0
    return secrets.randbits(N)


def getRandomNBitInteger(N: int) -> int:
    """
    Generate a random integer with exactly N bits.
    
    Args:
        N: Number of bits
        
    Returns:
        Random N-bit integer
    """
    if N <= 0:
        return 0
    
    # Generate N-bit number with MSB set
    n = secrets.randbits(N)
    n |= (1 << (N - 1))  # Ensure exactly N bits
    return n


def getRandomRange(a: int, b: int) -> int:
    """
    Generate a random integer in range [a, b).
    
    Args:
        a: Lower bound (inclusive)
        b: Upper bound (exclusive)
        
    Returns:
        Random integer in range
    """
    if a >= b:
        raise ValueError("a must be less than b")
    return secrets.randbelow(b - a) + a 