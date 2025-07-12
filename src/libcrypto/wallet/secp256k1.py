"""
Simple secp256k1 Elliptic Curve Implementation

This module provides basic secp256k1 elliptic curve operations using pure Python.
This is a minimal implementation for compatibility with the wallet library.
"""

from typing import Tuple, Optional
from ..Util.constants import (
    SECP256K1_P, SECP256K1_N, SECP256K1_GX, SECP256K1_GY, 
    SECP256K1_A, SECP256K1_B
)


class Secp256k1Point:
    """
    A point on the secp256k1 elliptic curve.
    
    Implements basic elliptic curve operations in Jacobian coordinates
    for efficiency.
    """
    
    def __init__(self, x: Optional[int] = None, y: Optional[int] = None, z: int = 1):
        """
        Initialize a point on secp256k1.
        
        Args:
            x: X coordinate (None for point at infinity).
            y: Y coordinate (None for point at infinity).
            z: Z coordinate (Jacobian coordinates, default 1).
        """
        self.x = x
        self.y = y
        self.z = z
    
    @property
    def is_infinity(self) -> bool:
        """Check if this is the point at infinity."""
        return self.x is None or self.y is None or self.z == 0
    
    def to_affine(self) -> Tuple[Optional[int], Optional[int]]:
        """
        Convert from Jacobian to affine coordinates.
        
        Returns:
            Tuple of (x, y) in affine coordinates.
        """
        if self.is_infinity:
            return None, None
        
        if self.z == 1:
            return self.x, self.y
        
        # Convert z^-1 mod p
        z_inv = pow(self.z, SECP256K1_P - 2, SECP256K1_P)
        z2_inv = (z_inv * z_inv) % SECP256K1_P
        z3_inv = (z2_inv * z_inv) % SECP256K1_P
        
        x = (self.x * z2_inv) % SECP256K1_P
        y = (self.y * z3_inv) % SECP256K1_P
        
        return x, y
    
    def double(self) -> 'Secp256k1Point':
        """
        Double this point (2 * P).
        
        Returns:
            A new point representing 2P.
        """
        if self.is_infinity:
            return Secp256k1Point()
        
        # For secp256k1, a = 0, so we can optimize
        y1_squared = (self.y * self.y) % SECP256K1_P
        s = (4 * self.x * y1_squared) % SECP256K1_P
        m = (3 * self.x * self.x) % SECP256K1_P  # Since a = 0
        
        x3 = (m * m - 2 * s) % SECP256K1_P
        y3 = (m * (s - x3) - 8 * y1_squared * y1_squared) % SECP256K1_P
        z3 = (2 * self.y * self.z) % SECP256K1_P
        
        return Secp256k1Point(x3, y3, z3)
    
    def add(self, other: 'Secp256k1Point') -> 'Secp256k1Point':
        """
        Add this point to another point.
        
        Args:
            other: The other point to add.
            
        Returns:
            A new point representing P + Q.
        """
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self
        
        # Convert to same Z coordinate
        if self.z != other.z:
            # Complex case - simplified for now
            x1, y1 = self.to_affine()
            x2, y2 = other.to_affine()
            
            if x1 == x2:
                if y1 == y2:
                    return self.double()
                else:
                    return Secp256k1Point()  # Point at infinity
            
            # Point addition in affine coordinates
            lambda_val = ((y2 - y1) * pow(x2 - x1, SECP256K1_P - 2, SECP256K1_P)) % SECP256K1_P
            x3 = (lambda_val * lambda_val - x1 - x2) % SECP256K1_P
            y3 = (lambda_val * (x1 - x3) - y1) % SECP256K1_P
            
            return Secp256k1Point(x3, y3, 1)
        
        # Same Z coordinate case
        u1, u2 = self.x, other.x
        s1, s2 = self.y, other.y
        
        if u1 == u2:
            if s1 == s2:
                return self.double()
            else:
                return Secp256k1Point()  # Point at infinity
        
        h = (u2 - u1) % SECP256K1_P
        r = (s2 - s1) % SECP256K1_P
        h2 = (h * h) % SECP256K1_P
        h3 = (h2 * h) % SECP256K1_P
        u1_h2 = (u1 * h2) % SECP256K1_P
        
        x3 = (r * r - h3 - 2 * u1_h2) % SECP256K1_P
        y3 = (r * (u1_h2 - x3) - s1 * h3) % SECP256K1_P
        z3 = (self.z * h) % SECP256K1_P
        
        return Secp256k1Point(x3, y3, z3)
    
    def multiply(self, scalar: int) -> 'Secp256k1Point':
        """
        Multiply this point by a scalar using double-and-add method.
        
        Args:
            scalar: The scalar to multiply by.
            
        Returns:
            A new point representing scalar * P.
        """
        if scalar == 0:
            return Secp256k1Point()
        if scalar == 1:
            return self
        
        # Reduce scalar modulo curve order
        scalar = scalar % SECP256K1_N
        
        # Double-and-add algorithm
        result = Secp256k1Point()  # Point at infinity
        addend = self
        
        while scalar:
            if scalar & 1:
                result = result.add(addend)
            addend = addend.double()
            scalar >>= 1
        
        return result


# Generator point for secp256k1
G = Secp256k1Point(SECP256K1_GX, SECP256K1_GY, 1)


def private_key_to_public_key(private_key: int, compressed: bool = True) -> bytes:
    """
    Convert a private key to a public key.
    
    Args:
        private_key: Private key as integer.
        compressed: Whether to return compressed public key.
        
    Returns:
        Public key bytes (33 bytes if compressed, 65 bytes if uncompressed).
    """
    # Multiply generator point by private key
    public_point = G.multiply(private_key)
    
    # Convert to affine coordinates
    x, y = public_point.to_affine()
    
    if x is None or y is None:
        raise ValueError("Invalid private key resulted in point at infinity")
    
    # Convert to bytes
    x_bytes = x.to_bytes(32, byteorder='big')
    
    if compressed:
        # Compressed format: 0x02 or 0x03 + x coordinate
        prefix = 0x02 if y % 2 == 0 else 0x03
        return bytes([prefix]) + x_bytes
    else:
        # Uncompressed format: 0x04 + x coordinate + y coordinate
        y_bytes = y.to_bytes(32, byteorder='big')
        return bytes([0x04]) + x_bytes + y_bytes


def public_key_to_point(public_key: bytes) -> Secp256k1Point:
    """
    Convert public key bytes to a point on the curve.
    
    Args:
        public_key: Public key bytes.
        
    Returns:
        Point on secp256k1 curve.
    """
    if len(public_key) == 33:
        # Compressed format
        prefix = public_key[0]
        x = int.from_bytes(public_key[1:], byteorder='big')
        
        # Calculate y coordinate
        # y^2 = x^3 + 7 (mod p)
        y_squared = (pow(x, 3, SECP256K1_P) + SECP256K1_B) % SECP256K1_P
        y = pow(y_squared, (SECP256K1_P + 1) // 4, SECP256K1_P)
        
        # Choose correct y based on prefix
        if (y % 2) != (prefix - 0x02):
            y = SECP256K1_P - y
        
        return Secp256k1Point(x, y, 1)
    
    elif len(public_key) == 65:
        # Uncompressed format
        if public_key[0] != 0x04:
            raise ValueError("Invalid uncompressed public key prefix")
        
        x = int.from_bytes(public_key[1:33], byteorder='big')
        y = int.from_bytes(public_key[33:], byteorder='big')
        
        return Secp256k1Point(x, y, 1)
    
    else:
        raise ValueError(f"Invalid public key length: {len(public_key)}")


__all__ = [
    'Secp256k1Point',
    'G',
    'private_key_to_public_key',
    'public_key_to_point'
]
 