"""
Internal Cryptographic Utilities

This module provides cryptographic utilities using only internal dependencies.
Includes HMAC and PBKDF2 implementations for zero-dependency operation.
"""

import struct
from typing import Optional
from ..Hash.SHA1 import SHA1Hash
from ..Hash.SHA256 import SHA256Hash
from ..Hash.HMAC import new
from ..Hash.SHA512 import SHA512Hash
from ..Hash.SHA1 import SHA1Hash


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte arrays of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


class HMAC:
    """
    HMAC implementation using internal hash functions.
    
    Implements HMAC as specified in RFC 2104 using only internal dependencies.
    """
    
    def __init__(self, key: bytes, hash_class=SHA256Hash):
        """
        Initialize HMAC with key and hash function.
        
        Args:
            key: The secret key bytes.
            hash_class: Hash function class (SHA256Hash or SHA1Hash). Default is SHA256Hash.
        """
        self.hash_class = hash_class
        self.block_size = 64  # Block size for SHA-1 and SHA-256
        self.digest_size = hash_class().digest_size
        
        # Prepare key
        if len(key) > self.block_size:
            # If key is longer than block size, hash it
            key = hash_class(key).digest()
        
        # Pad key to block size
        if len(key) < self.block_size:
            key = key + b'\x00' * (self.block_size - len(key))
        
        # Create inner and outer padded keys
        self.inner_key = _xor_bytes(key, b'\x36' * self.block_size)
        self.outer_key = _xor_bytes(key, b'\x5C' * self.block_size)
        
        # Initialize inner hash
        self.inner_hash = hash_class(self.inner_key)
    
    def update(self, data: bytes) -> 'HMAC':
        """
        Update HMAC with data.
        
        Args:
            data: Data bytes to authenticate.
            
        Returns:
            Self for chaining.
        """
        self.inner_hash.update(data)
        return self
    
    def digest(self) -> bytes:
        """
        Compute HMAC digest.
        
        Returns:
            HMAC digest bytes.
        """
        # Finalize inner hash
        inner_digest = self.inner_hash.digest()
        
        # Compute outer hash
        outer_hash = self.hash_class(self.outer_key)
        outer_hash.update(inner_digest)
        
        return outer_hash.digest()
    
    def hexdigest(self) -> str:
        """
        Compute HMAC digest as hex string.
        
        Returns:
            HMAC digest as hex string.
        """
        return self.digest().hex()
    
    def copy(self) -> 'HMAC':
        """
        Create a copy of the HMAC object.
        
        Returns:
            A new HMAC object with the same state.
        """
        new_hmac = HMAC.__new__(HMAC)
        new_hmac.hash_class = self.hash_class
        new_hmac.block_size = self.block_size
        new_hmac.digest_size = self.digest_size
        new_hmac.inner_key = self.inner_key
        new_hmac.outer_key = self.outer_key
        new_hmac.inner_hash = self.inner_hash.copy()
        return new_hmac


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """
    Compute HMAC-SHA256.
    
    Args:
        key: Secret key bytes.
        message: Message bytes to authenticate.
        
    Returns:
        HMAC-SHA256 digest bytes.
    """
    hmac = HMAC(key, SHA256Hash)
    hmac.update(message)
    return hmac.digest()


def hmac_sha512(key: bytes, message: bytes) -> bytes:
    """
    Compute HMAC-SHA512 using Python's built-in hashlib.
    
    Args:
        key: Secret key bytes.
        message: Message bytes to authenticate.
        
    Returns:
        HMAC-SHA512 digest bytes (64 bytes).
    """
    return new(key, message, SHA512Hash).digest()


def pbkdf2_hmac_sha256(password: bytes, salt: bytes, iterations: int, dk_length: int) -> bytes:
    """
    PBKDF2 key derivation using HMAC-SHA256.
    
    Implements PBKDF2 as specified in RFC 2898 using only internal dependencies.
    
    Args:
        password: Password bytes.
        salt: Salt bytes.
        iterations: Number of iterations (should be >= 1000).
        dk_length: Desired key length in bytes.
        
    Returns:
        Derived key bytes of specified length.
    """
    if iterations < 1:
        raise ValueError("Iterations must be at least 1")
    
    if dk_length < 1:
        raise ValueError("dk_length must be at least 1")
    
    # Hash length for SHA-256
    h_length = 32
    
    # Number of blocks needed
    blocks_needed = (dk_length + h_length - 1) // h_length
    
    derived_key = b''
    
    for block_num in range(1, blocks_needed + 1):
        # U_1 = PRF(password, salt || INT(block_num))
        block_salt = salt + struct.pack('>I', block_num)
        u = hmac_sha256(password, block_salt)
        result = u
        
        # U_2 through U_iterations
        for _ in range(iterations - 1):
            u = hmac_sha256(password, u)
            result = _xor_bytes(result, u)
        
        derived_key += result
    
    # Return first dk_length bytes
    return derived_key[:dk_length]


def pbkdf2_sha1(password: bytes, salt: bytes, iterations: int, dk_length: int) -> bytes:
    """
    PBKDF2 key derivation using HMAC-SHA1.
    
    Args:
        password: Password bytes.
        salt: Salt bytes.
        iterations: Number of iterations.
        dk_length: Desired key length in bytes.
        
    Returns:
        Derived key bytes of specified length.
    """
    if iterations < 1:
        raise ValueError("Iterations must be at least 1")
    
    if dk_length < 1:
        raise ValueError("dk_length must be at least 1")
    
    # Hash length for SHA-1
    h_length = 20
    
    # Number of blocks needed
    blocks_needed = (dk_length + h_length - 1) // h_length
    
    derived_key = b''
    
    for block_num in range(1, blocks_needed + 1):
        # U_1 = PRF(password, salt || INT(block_num))
        block_salt = salt + struct.pack('>I', block_num)
        
        hmac = HMAC(password, SHA1Hash.new())
        hmac.update(block_salt)
        u = hmac.digest()
        result = u
        
        # U_2 through U_iterations
        for _ in range(iterations - 1):
            hmac = HMAC(password, SHA1Hash.new())
            hmac.update(u)
            u = hmac.digest()
            result = _xor_bytes(result, u)
        
        derived_key += result
    
    # Return first dk_length bytes
    return derived_key[:dk_length]


# Keccak implementation for Ethereum
def _keccak_f(state):
    """Keccak-f[1600] permutation function."""
    RNDC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x8000000000008003,
        0x8000000080008002, 0x8000000080000080, 0x000000000000800A,
        0x800000008000000A, 0x8000000080008081, 0x8000000000008080,
        0x0000000080000001, 0x8000000080008008
    ]
    
    ROT = [
        [0, 1, 62, 28, 27],
        [36, 44, 6, 55, 20],
        [3, 10, 43, 25, 39],
        [41, 45, 15, 21, 8],
        [18, 2, 61, 56, 14]
    ]
    
    for round_idx in range(24):
        # Theta step
        c = [0] * 5
        for x in range(5):
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
        
        d = [0] * 5
        for x in range(5):
            d[x] = c[(x + 4) % 5] ^ _rotl64(c[(x + 1) % 5], 1)
        
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        
        # Rho and Pi steps
        new_state = [0] * 25
        for x in range(5):
            for y in range(5):
                new_state[((2 * x + 3 * y) % 5) + 5 * x] = _rotl64(state[x + 5 * y], ROT[y][x])
        state[:] = new_state
        
        # Chi step
        new_state = [0] * 25
        for x in range(5):
            for y in range(5):
                new_state[x + 5 * y] = state[x + 5 * y] ^ ((~state[((x + 1) % 5) + 5 * y]) & state[((x + 2) % 5) + 5 * y])
        state[:] = new_state
        
        # Iota step
        state[0] ^= RNDC[round_idx]
    
    return state


def _rotl64(n, b):
    """64-bit left rotation."""
    n &= 0xFFFFFFFFFFFFFFFF
    return ((n << b) | (n >> (64 - b))) & 0xFFFFFFFFFFFFFFFF


def keccak256(data: bytes) -> bytes:
    """
    Keccak-256 hash function.
    
    Args:
        data: Input data bytes.
        
    Returns:
        32-byte Keccak-256 hash.
    """
    # Keccak-256 parameters
    rate = 1088  # bits
    capacity = 512  # bits
    output_length = 32  # bytes
    
    # Convert rate and capacity to bytes
    rate_bytes = rate // 8  # 136 bytes
    
    # Initialize state (1600 bits = 200 bytes = 25 uint64)
    state = [0] * 25
    
    # Padding
    padded_data = data + b'\x01'  # Keccak padding
    while len(padded_data) % rate_bytes != 0:
        padded_data += b'\x00'
    padded_data = padded_data[:-1] + bytes([padded_data[-1] | 0x80])
    
    # Absorb phase
    for i in range(0, len(padded_data), rate_bytes):
        block = padded_data[i:i + rate_bytes]
        
        # XOR block into state
        for j in range(0, len(block), 8):
            if j + 8 <= len(block):
                chunk = block[j:j + 8]
                # Convert 8 bytes to uint64 (little endian)
                value = int.from_bytes(chunk, byteorder='little')
                state[j // 8] ^= value
        
        # Apply permutation
        state = _keccak_f(state)
    
    # Squeeze phase
    output = b''
    while len(output) < output_length:
        # Extract rate_bytes from state
        for i in range(min(rate_bytes // 8, (output_length - len(output) + 7) // 8)):
            chunk = state[i].to_bytes(8, byteorder='little')
            output += chunk
            if len(output) >= output_length:
                break
        
        if len(output) < output_length:
            state = _keccak_f(state)
    
    return output[:output_length]


# BIP39 specific PBKDF2 function
def bip39_pbkdf2(mnemonic: str, passphrase: str = "") -> bytes:
    """
    BIP39 PBKDF2 key derivation.
    
    Args:
        mnemonic: BIP39 mnemonic phrase.
        passphrase: Optional passphrase. Default is empty string.
        
    Returns:
        64-byte seed for HD wallet generation.
    """
    # BIP39 specifies UTF-8 encoding and "mnemonic" prefix for salt
    password = mnemonic.encode('utf-8')
    salt = ('mnemonic' + passphrase).encode('utf-8')
    
    # BIP39 specifies 2048 iterations and 64-byte output
    return pbkdf2_hmac_sha256(password, salt, 2048, 64) 