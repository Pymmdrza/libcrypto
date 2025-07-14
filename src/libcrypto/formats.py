"""
Format Conversion Utilities

This module provides utilities for converting between different cryptocurrency
key and address formats including Base58 encoding/decoding, WIF format, and
various hex/bytes conversions.
"""

from typing import Union, Tuple

from .hash import double_sha256
from .constants import BASE58_ALPHABET, ADDRESS_VERSIONS


class InvalidFormatError(ValueError):
    """Raised when a format conversion fails."""
    pass


def bytes_to_int(data: bytes, byteorder: str = 'big') -> int:
    """Converts a byte string to an integer."""
    return int.from_bytes(data, byteorder=byteorder)


def int_to_bytes(value: int, length: int = 0, byteorder: str = 'big') -> bytes:
    """Converts an integer to a byte string of a specified or minimal length."""
    if value < 0:
        raise ValueError("Negative numbers are not supported.")
    if length == 0:
        if value == 0:
            return b'\x00'
        length = (value.bit_length() + 7) // 8
    try:
        return value.to_bytes(length, byteorder=byteorder)
    except OverflowError as e:
        raise ValueError(f"Value {value} is too large for {length} bytes.") from e


def bytes_to_hex(data: bytes) -> str:
    """Converts a byte string to its hexadecimal representation."""
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """Converts a hexadecimal string to a byte string."""
    if hex_str.startswith(('0x', '0X')):
        hex_str = hex_str[2:]
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    try:
        return bytes.fromhex(hex_str)
    except ValueError as e:
        raise InvalidFormatError(f"Invalid hexadecimal string: {e}") from e


def base58_encode(data: bytes, alphabet: str = BASE58_ALPHABET) -> str:
    """Encode bytes to Base58 string."""
    if not data:
        return ""
    num = bytes_to_int(data)
    encoded = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = alphabet[remainder] + encoded

    # Add leading zeros
    leading_zeros = len(data) - len(data.lstrip(b'\x00'))
    return alphabet[0] * leading_zeros + encoded


def base58_decode(encoded: str, alphabet: str = BASE58_ALPHABET) -> bytes:
    """Decode Base58 string to bytes."""
    if not encoded:
        return b""
    num = 0
    for char in encoded:
        if char not in alphabet:
            raise InvalidFormatError(f"Invalid character '{char}' in Base58 string")
        num = num * 58 + alphabet.index(char)

    decoded = int_to_bytes(num)

    # Add leading zeros
    leading_zeros = len(encoded) - len(encoded.lstrip(alphabet[0]))
    return b'\x00' * leading_zeros + decoded


def base58_check_encode(data: bytes, alphabet: str = BASE58_ALPHABET) -> str:
    """Encode bytes to Base58Check (Base58 with checksum)."""
    checksum = double_sha256(data)[:4]
    return base58_encode(data + checksum, alphabet)


def base58_check_decode(encoded: str, alphabet: str = BASE58_ALPHABET) -> bytes:
    """Decode Base58Check string to bytes and verify checksum."""
    decoded = base58_decode(encoded, alphabet)
    if len(decoded) < 4:
        raise InvalidFormatError("Base58Check string too short")

    data, checksum = decoded[:-4], decoded[-4:]
    expected_checksum = double_sha256(data)[:4]

    if checksum != expected_checksum:
        raise InvalidFormatError("Invalid Base58Check checksum")

    return data


def private_key_to_wif(private_key: Union[bytes, int], compressed: bool = True, network: str = 'bitcoin') -> str:
    """Convert a private key to Wallet Import Format (WIF)."""
    if isinstance(private_key, int):
        private_key = int_to_bytes(private_key, 32)
    elif not (isinstance(private_key, bytes) and len(private_key) == 32):
        raise InvalidFormatError("Private key must be a 32-byte string or an integer.")

    if network not in ADDRESS_VERSIONS:
        raise InvalidFormatError(f"Unsupported network: {network}")

    version_byte = ADDRESS_VERSIONS[network]['private']
    payload = bytes([version_byte]) + private_key

    if compressed:
        payload += b'\x01'

    return base58_check_encode(payload)


def wif_to_private_key(wif: str) -> Tuple[bytes, bool, str]:
    """Convert WIF to private key."""
    try:
        decoded = base58_check_decode(wif)
    except InvalidFormatError as e:
        raise InvalidFormatError(f"Invalid WIF format: {e}") from e

    if len(decoded) not in [33, 34]:
        raise InvalidFormatError(f"Invalid WIF length: {len(decoded)}")

    version_byte = decoded[0]
    network = None
    for net_name, versions in ADDRESS_VERSIONS.items():
        if versions['private'] == version_byte:
            network = net_name
            break

    if network is None:
        raise InvalidFormatError(f"Unknown WIF version byte: {version_byte}")

    private_key = decoded[1:33]

    if len(decoded) == 34:
        if decoded[33] != 0x01:
            raise InvalidFormatError(f"Invalid compression flag: {decoded[33]}")
        is_compressed = True
    else:
        is_compressed = False

    return private_key, is_compressed, network


__all__ = [
    'base58_encode', 'base58_decode', 'base58_check_encode', 'base58_check_decode',
    'private_key_to_wif', 'wif_to_private_key', 'bytes_to_hex', 'hex_to_bytes',
    'int_to_bytes', 'bytes_to_int', 'InvalidFormatError'
]
