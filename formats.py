"""
Format Conversion Utilities

This module provides utilities for converting between different cryptocurrency 
key and address formats including Base58 encoding/decoding, WIF format, and
various hex/bytes conversions.
"""

from typing import Union, Optional

from ..Hash.SHA256 import SHA256Hash
from ..Util.constants import BASE58_ALPHABET, ADDRESS_VERSIONS
from ..Util.number import bytes_to_long, long_to_bytes


class InvalidFormatError(ValueError):
    """Raised when a format conversion fails."""
    pass


def _double_sha256(data: bytes) -> bytes:
    """
    Perform double SHA256 hash (used for checksums in Bitcoin-like addresses).
    
    Args:
        data: The data to hash.
        
    Returns:
        The double SHA256 hash.
    """
    first_hash = SHA256Hash(data).digest()
    return SHA256Hash(first_hash).digest()


def base58_encode(data: bytes, alphabet: str = BASE58_ALPHABET) -> str:
    """
    Encode bytes to Base58 string.
    
    Args:
        data: The bytes to encode.
        alphabet: The Base58 alphabet to use. Default is Bitcoin alphabet.
        
    Returns:
        The Base58 encoded string.
        
    Example:
        >>> encoded = base58_encode(b'Hello World')
        >>> print(encoded)
        JxF12TrwUP45BMd
    """
    if not data:
        return ""
    
    # Convert bytes to integer
    num = bytes_to_long(data)
    
    # Handle leading zeros
    leading_zeros = 0
    for byte in data:
        if byte == 0:
            leading_zeros += 1
        else:
            break
    
    # Convert to base58
    encoded = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = alphabet[remainder] + encoded
    
    # Add leading zeros as first character of alphabet
    encoded = alphabet[0] * leading_zeros + encoded
    
    return encoded


def base58_decode(encoded: str, alphabet: str = BASE58_ALPHABET) -> bytes:
    """
    Decode Base58 string to bytes.
    
    Args:
        encoded: The Base58 encoded string.
        alphabet: The Base58 alphabet to use. Default is Bitcoin alphabet.
        
    Returns:
        The decoded bytes.
        
    Raises:
        InvalidFormatError: If the string contains invalid characters.
        
    Example:
        >>> decoded = base58_decode('JxF12TrwUP45BMd')
        >>> print(decoded)
        b'Hello World'
    """
    if not encoded:
        return b""
    
    # Count leading zeros
    leading_zeros = 0
    for char in encoded:
        if char == alphabet[0]:
            leading_zeros += 1
        else:
            break
    
    # Convert to integer
    num = 0
    for char in encoded:
        if char not in alphabet:
            raise InvalidFormatError(f"Invalid character '{char}' in Base58 string")
        num = num * 58 + alphabet.index(char)
    
    # Convert to bytes
    decoded = long_to_bytes(num) if num > 0 else b""
    
    # Add leading zero bytes
    decoded = b'\x00' * leading_zeros + decoded
    
    return decoded


def base58_check_encode(data: bytes, alphabet: str = BASE58_ALPHABET) -> str:
    """
    Encode bytes to Base58Check (Base58 with checksum).
    
    Args:
        data: The bytes to encode.
        alphabet: The Base58 alphabet to use.
        
    Returns:
        The Base58Check encoded string.
    """
    # Calculate checksum (first 4 bytes of double SHA256)
    checksum = _double_sha256(data)[:4]
    
    # Append checksum and encode
    return base58_encode(data + checksum, alphabet)


def base58_check_decode(encoded: str, alphabet: str = BASE58_ALPHABET) -> bytes:
    """
    Decode Base58Check string to bytes and verify checksum.
    
    Args:
        encoded: The Base58Check encoded string.
        alphabet: The Base58 alphabet to use.
        
    Returns:
        The decoded bytes without checksum.
        
    Raises:
        InvalidFormatError: If checksum verification fails.
    """
    decoded = base58_decode(encoded, alphabet)
    
    if len(decoded) < 4:
        raise InvalidFormatError("Base58Check string too short")
    
    # Split data and checksum
    data = decoded[:-4]
    checksum = decoded[-4:]
    
    # Verify checksum
    expected_checksum = _double_sha256(data)[:4]
    if checksum != expected_checksum:
        raise InvalidFormatError("Invalid Base58Check checksum")
    
    return data


def private_key_to_wif(private_key: Union[bytes, int, str], 
                      compressed: bool = True,
                      network: str = 'bitcoin') -> str:
    """
    Convert a private key to Wallet Import Format (WIF).
    
    Args:
        private_key: The private key as bytes, integer, or hex string.
        compressed: Whether to use compressed WIF format. Default is True.
        network: The network type ('bitcoin', 'testnet', etc.). Default is 'bitcoin'.
        
    Returns:
        The WIF encoded private key string.
        
    Raises:
        InvalidFormatError: If private key is invalid.
        
    Example:
        >>> wif = private_key_to_wif(0x01, compressed=True)
        >>> print(wif)
        KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
    """
    # Convert private key to bytes
    if isinstance(private_key, str):
        try:
            private_key = bytes.fromhex(private_key)
        except ValueError as e:
            raise InvalidFormatError(f"Invalid hex private key: {e}") from e
    elif isinstance(private_key, int):
        private_key = private_key.to_bytes(32, byteorder='big')
    elif isinstance(private_key, bytes):
        if len(private_key) != 32:
            raise InvalidFormatError(f"Private key must be 32 bytes, got {len(private_key)}")
    else:
        raise InvalidFormatError("Private key must be bytes, int, or hex string")
    
    # Get version byte for network
    if network not in ADDRESS_VERSIONS:
        raise InvalidFormatError(f"Unsupported network: {network}")
    
    version_byte = ADDRESS_VERSIONS[network]['private']
    
    # Create WIF payload
    payload = version_byte.to_bytes(1, byteorder='big') + private_key
    
    # Add compression flag if compressed
    if compressed:
        payload += b'\x01'
    
    return base58_check_encode(payload)


def wif_to_private_key(wif: str) -> tuple[bytes, bool, str]:
    """
    Convert WIF (Wallet Import Format) to private key.
    
    Args:
        wif: The WIF encoded private key string.
        
    Returns:
        A tuple of (private_key_bytes, is_compressed, network).
        
    Raises:
        InvalidFormatError: If WIF is invalid.
        
    Example:
        >>> private_key, compressed, network = wif_to_private_key('KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn')
        >>> print(private_key.hex(), compressed, network)
        0000000000000000000000000000000000000000000000000000000000000001 True bitcoin
    """
    try:
        decoded = base58_check_decode(wif)
    except InvalidFormatError as e:
        raise InvalidFormatError(f"Invalid WIF format: {e}") from e
    
    if len(decoded) not in [33, 34]:
        raise InvalidFormatError(f"Invalid WIF length: {len(decoded)}")
    
    # Extract version byte
    version_byte = decoded[0]
    
    # Find network from version byte
    network = None
    for net_name, versions in ADDRESS_VERSIONS.items():
        if versions['private'] == version_byte:
            network = net_name
            break
    
    if network is None:
        raise InvalidFormatError(f"Unknown WIF version byte: {version_byte}")
    
    # Extract private key
    if len(decoded) == 34:
        # Compressed WIF
        if decoded[-1] != 0x01:
            raise InvalidFormatError("Invalid compression flag in WIF")
        private_key = decoded[1:-1]
        is_compressed = True
    else:
        # Uncompressed WIF
        private_key = decoded[1:]
        is_compressed = False
    
    if len(private_key) != 32:
        raise InvalidFormatError(f"Invalid private key length: {len(private_key)}")
    
    return private_key, is_compressed, network


def bytes_to_hex(data: bytes) -> str:
    """
    Convert bytes to hex string.
    
    Args:
        data: The bytes to convert.
        
    Returns:
        The hex string (without '0x' prefix).
        
    Example:
        >>> hex_str = bytes_to_hex(b'\\x01\\x02\\x03')
        >>> print(hex_str)
        010203
    """
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """
    Convert hex string to bytes.
    
    Args:
        hex_str: The hex string (with or without '0x' prefix).
        
    Returns:
        The bytes.
        
    Raises:
        InvalidFormatError: If hex string is invalid.
        
    Example:
        >>> data = hex_to_bytes('010203')
        >>> print(data)
        b'\\x01\\x02\\x03'
    """
    # Remove '0x' prefix if present
    if hex_str.startswith('0x') or hex_str.startswith('0X'):
        hex_str = hex_str[2:]
    
    try:
        return bytes.fromhex(hex_str)
    except ValueError as e:
        raise InvalidFormatError(f"Invalid hex string: {e}") from e


def int_to_bytes(value: int, length: int = 32, byteorder: str = 'big') -> bytes:
    """
    Convert integer to bytes with specified length.
    
    Args:
        value: The integer to convert.
        length: The desired byte length. Default is 32.
        byteorder: The byte order ('big' or 'little'). Default is 'big'.
        
    Returns:
        The bytes representation.
        
    Raises:
        InvalidFormatError: If integer is too large for specified length.
    """
    try:
        return value.to_bytes(length, byteorder=byteorder)
    except OverflowError as e:
        raise InvalidFormatError(f"Integer too large for {length} bytes: {e}") from e


def bytes_to_int(data: bytes, byteorder: str = 'big') -> int:
    """
    Convert bytes to integer.
    
    Args:
        data: The bytes to convert.
        byteorder: The byte order ('big' or 'little'). Default is 'big'.
        
    Returns:
        The integer value.
    """
    return int.from_bytes(data, byteorder=byteorder)


# Export main functions
__all__ = [
    'base58_encode',
    'base58_decode', 
    'base58_check_encode',
    'base58_check_decode',
    'private_key_to_wif',
    'wif_to_private_key',
    'bytes_to_hex',
    'hex_to_bytes',
    'int_to_bytes',
    'bytes_to_int',
    'InvalidFormatError'
] 