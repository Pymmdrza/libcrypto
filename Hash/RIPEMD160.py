"""
RIPEMD160 hash algorithm implementation.

This module provides RIPEMD160 hashing functionality using a pure Python
implementation based on pycryptodome's approach.
"""

import struct
from typing import Union, Optional


class RIPEMD160Hash:
    """
    A RIPEMD160 hasher object.
    
    This class provides RIPEMD160 hashing functionality using pure Python
    implementation adapted from pycryptodome.
    """
    
    digest_size = 20
    block_size = 64
    oid = "1.3.36.3.2.1"  # RIPEMD160 OID
    
    def __init__(self, data: Optional[bytes] = None):
        """
        Initialize a new RIPEMD160 hash object.
        
        Args:
            data: Optional initial data to hash.
        """
        # Initial hash values for RIPEMD160
        self._h = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
        ]
        self._buffer = b''
        self._counter = 0
        
        if data is not None:
            self.update(data)
    
    def _f(self, j: int, x: int, y: int, z: int) -> int:
        """RIPEMD160 auxiliary functions."""
        if j < 16:
            return x ^ y ^ z
        elif j < 32:
            return (x & y) | (~x & z)
        elif j < 48:
            return (x | ~y) ^ z
        elif j < 64:
            return (x & z) | (y & ~z)
        else:
            return x ^ (y | ~z)
    
    def _K(self, j: int) -> int:
        """RIPEMD160 constants."""
        if j < 16:
            return 0x00000000
        elif j < 32:
            return 0x5A827999
        elif j < 48:
            return 0x6ED9EBA1
        elif j < 64:
            return 0x8F1BBCDC
        else:
            return 0xA953FD4E
    
    def _Kh(self, j: int) -> int:
        """RIPEMD160 constants for parallel line."""
        if j < 16:
            return 0x50A28BE6
        elif j < 32:
            return 0x5C4DD124
        elif j < 48:
            return 0x6D703EF3
        elif j < 64:
            return 0x7A6D76E9
        else:
            return 0x00000000
    
    def _padandsplit(self, message: bytes) -> list:
        """
        Pad the message and split into 512-bit blocks.
        """
        msg_len = len(message)
        message += b'\x80'
        message += b'\x00' * ((55 - msg_len) % 64)
        message += struct.pack('<Q', msg_len * 8)
        return [message[i:i+64] for i in range(0, len(message), 64)]
    
    def _process_block(self, block: bytes) -> None:
        """Process a single 512-bit block."""
        # Convert block to 16 32-bit words
        x = list(struct.unpack('<16L', block))
        
        # Initialize working variables
        al, bl, cl, dl, el = self._h
        ar, br, cr, dr, er = self._h
        
        # Selection of message word
        r = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
             7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
             3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
             1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
             4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
        
        rh = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
              6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
              15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
              8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
              12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
        
        # Amount of rotate left
        s = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
             7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
             11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
             11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
             9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
        
        sh = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
              9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
              9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
              15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
              8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
        
        def _rotleft(n: int, b: int) -> int:
            """Rotate left."""
            return ((n << b) | (n >> (32 - b))) & 0xffffffff
        
        # Main loop
        for j in range(80):
            # Left line
            t = _rotleft((al + self._f(j, bl, cl, dl) + x[r[j]] + self._K(j)) & 0xffffffff, s[j]) + el
            al, bl, cl, dl, el = el & 0xffffffff, t & 0xffffffff, bl, _rotleft(cl, 10), dl
            
            # Right line  
            t = _rotleft((ar + self._f(79-j, br, cr, dr) + x[rh[j]] + self._Kh(j)) & 0xffffffff, sh[j]) + er
            ar, br, cr, dr, er = er & 0xffffffff, t & 0xffffffff, br, _rotleft(cr, 10), dr
        
        # Combine results
        t = (self._h[1] + cl + dr) & 0xffffffff
        self._h[1] = (self._h[2] + dl + er) & 0xffffffff
        self._h[2] = (self._h[3] + el + ar) & 0xffffffff
        self._h[3] = (self._h[4] + al + br) & 0xffffffff
        self._h[4] = (self._h[0] + bl + cr) & 0xffffffff
        self._h[0] = t
    
    def update(self, data: Union[bytes, bytearray]) -> None:
        """
        Update the hash object with new data.
        
        Args:
            data: The data to hash.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        self._buffer += data
        self._counter += len(data)
        
        # Process complete blocks
        while len(self._buffer) >= 64:
            self._process_block(self._buffer[:64])
            self._buffer = self._buffer[64:]
    
    def digest(self) -> bytes:
        """
        Return the digest of the data.
        
        Returns:
            The hash digest as bytes.
        """
        # Create a copy for final processing
        mdi = self._counter % 64
        length = self._counter * 8
        
        # Padding
        if mdi < 56:
            padlen = 56 - mdi
        else:
            padlen = 120 - mdi
        
        padding = b'\x80' + (b'\x00' * (padlen - 1))
        
        # Create temporary hash object for processing
        temp_h = self._h[:]
        temp_buffer = self._buffer + padding + struct.pack('<Q', length)
        
        # Process remaining blocks
        for i in range(0, len(temp_buffer), 64):
            if i + 64 <= len(temp_buffer):
                block = temp_buffer[i:i+64]
                x = list(struct.unpack('<16L', block))
                
                # Same processing as _process_block but on temp_h
                al, bl, cl, dl, el = temp_h
                ar, br, cr, dr, er = temp_h
                
                # Use the same tables and processing as above
                r = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                     7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
                     3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
                     1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
                     4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
                
                rh = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
                      6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
                      15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
                      8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
                      12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
                
                s = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
                     7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
                     11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
                     11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
                     9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
                
                sh = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
                      9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
                      9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
                      15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
                      8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
                
                def _rotleft(n: int, b: int) -> int:
                    return ((n << b) | (n >> (32 - b))) & 0xffffffff
                
                for j in range(80):
                    t = _rotleft((al + self._f(j, bl, cl, dl) + x[r[j]] + self._K(j)) & 0xffffffff, s[j]) + el
                    al, bl, cl, dl, el = el & 0xffffffff, t & 0xffffffff, bl, _rotleft(cl, 10), dl
                    
                    t = _rotleft((ar + self._f(79-j, br, cr, dr) + x[rh[j]] + self._Kh(j)) & 0xffffffff, sh[j]) + er
                    ar, br, cr, dr, er = er & 0xffffffff, t & 0xffffffff, br, _rotleft(cr, 10), dr
                
                t = (temp_h[1] + cl + dr) & 0xffffffff
                temp_h[1] = (temp_h[2] + dl + er) & 0xffffffff
                temp_h[2] = (temp_h[3] + el + ar) & 0xffffffff
                temp_h[3] = (temp_h[4] + al + br) & 0xffffffff
                temp_h[4] = (temp_h[0] + bl + cr) & 0xffffffff
                temp_h[0] = t
        
        return struct.pack('<5L', *temp_h)
    
    def hexdigest(self) -> str:
        """
        Return the digest of the data as a hex string.
        
        Returns:
            The hash digest as a hexadecimal string.
        """
        return self.digest().hex()
    
    def copy(self) -> 'RIPEMD160Hash':
        """
        Return a copy of the hash object.
        
        Returns:
            A new RIPEMD160Hash object with the same state.
        """
        new_hash = RIPEMD160Hash()
        new_hash._h = self._h[:]
        new_hash._buffer = self._buffer
        new_hash._counter = self._counter
        return new_hash


# Factory function for compatibility
def new(data: Optional[bytes] = None) -> RIPEMD160Hash:
    """
    Create a new RIPEMD160 hash object.
    
    Args:
        data: Optional initial data to hash.
        
    Returns:
        A new RIPEMD160Hash object.
    """
    return RIPEMD160Hash(data)


# Convenience function
def ripemd160(data: bytes) -> bytes:
    """
    Compute RIPEMD160 hash of data in one call.
    
    Args:
        data: The data to hash.
        
    Returns:
        The RIPEMD160 hash digest.
    """
    return RIPEMD160Hash(data).digest()


# Module-level constants
digest_size = RIPEMD160Hash.digest_size
block_size = RIPEMD160Hash.block_size 