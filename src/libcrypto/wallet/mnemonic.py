"""
BIP39 Mnemonic Phrase Implementation

This module provides comprehensive BIP39 mnemonic phrase functionality including:
- Secure mnemonic generation with proper entropy
- Mnemonic validation with checksum verification  
- Mnemonic to seed conversion with PBKDF2
- Support for multiple word counts (12, 15, 18, 21, 24)
- Optional passphrase support
"""
import secrets
from typing import List, Optional, Union

from ..Hash.SHA256 import SHA256Hash
from ..Random import get_random_bytes
from ..wallet.crypto_utils import bip39_pbkdf2
from ..Util.constants import (
    BIP39_WORD_LIST,
    BIP39_ENTROPY_BITS,
    BIP39_CHECKSUM_BITS,
    PBKDF2_ITERATIONS,
    PBKDF2_HMAC_DKLEN,
    VALID_MNEMONIC_LENGTHS,
    ERROR_MESSAGES
)


class InvalidMnemonicError(ValueError):
    """Raised when a mnemonic phrase is invalid."""
    pass


class InvalidEntropyError(ValueError):
    """Raised when entropy is invalid."""
    pass


def _entropy_to_checksum(entropy: bytes) -> int:
    """
    Calculate checksum for entropy according to BIP39.
    
    Args:
        entropy: The entropy bytes.
        
    Returns:
        The checksum as an integer.
    """
    sha256_hash = SHA256Hash(entropy).digest()
    return sha256_hash[0]


def _entropy_to_mnemonic(entropy: bytes) -> str:
    """
    Convert entropy to a mnemonic phrase.
    
    Args:
        entropy: The entropy bytes (16, 20, 24, 28, or 32 bytes).
        
    Returns:
        A BIP39 mnemonic phrase string.
        
    Raises:
        InvalidEntropyError: If entropy length is invalid.
    """
    entropy_bits = len(entropy) * 8
    if entropy_bits not in BIP39_ENTROPY_BITS.values():
        raise InvalidEntropyError(f"Invalid entropy length: {len(entropy)} bytes")

    # Calculate checksum
    checksum_byte = _entropy_to_checksum(entropy)
    checksum_bits = BIP39_CHECKSUM_BITS[entropy_bits // 32 * 3]

    # Convert entropy to integer
    entropy_int = int.from_bytes(entropy, byteorder='big')

    # Append checksum bits
    checksum_int = checksum_byte >> (8 - checksum_bits)
    combined_int = (entropy_int << checksum_bits) | checksum_int

    # Split into 11-bit groups for word indices
    word_count = (entropy_bits + checksum_bits) // 11
    words = []

    for i in range(word_count):
        # Extract 11 bits from the right
        word_index = combined_int & 0x7FF  # 0x7FF = 2047 = 2^11 - 1
        words.append(BIP39_WORD_LIST[word_index])
        combined_int >>= 11

    # Reverse the words since we extracted from right to left
    words.reverse()
    return ' '.join(words)


def _mnemonic_to_entropy(mnemonic: str) -> bytes:
    """
    Convert a mnemonic phrase back to entropy.
    
    Args:
        mnemonic: The mnemonic phrase string.
        
    Returns:
        The original entropy bytes.
        
    Raises:
        InvalidMnemonicError: If mnemonic is invalid.
    """
    words = mnemonic.strip().split()
    word_count = len(words)

    if word_count not in VALID_MNEMONIC_LENGTHS:
        raise InvalidMnemonicError(ERROR_MESSAGES['invalid_mnemonic_length'])

    # Convert words to indices
    try:
        word_indices = [BIP39_WORD_LIST.index(word) for word in words]
    except ValueError as e:
        raise InvalidMnemonicError(ERROR_MESSAGES['invalid_mnemonic_word']) from e

    # Combine indices into a single integer
    combined_int = 0
    for index in word_indices:
        combined_int = (combined_int << 11) | index

    # Calculate entropy and checksum bit lengths
    entropy_bits = BIP39_ENTROPY_BITS[word_count]
    checksum_bits = BIP39_CHECKSUM_BITS[word_count]

    # Extract entropy and checksum
    entropy_mask = (1 << entropy_bits) - 1
    entropy_int = combined_int >> checksum_bits
    checksum_int = combined_int & ((1 << checksum_bits) - 1)

    # Convert entropy to bytes
    entropy_bytes = entropy_int.to_bytes(entropy_bits // 8, byteorder='big')

    # Verify checksum
    expected_checksum_byte = _entropy_to_checksum(entropy_bytes)
    expected_checksum = expected_checksum_byte >> (8 - checksum_bits)

    if checksum_int != expected_checksum:
        raise InvalidMnemonicError(ERROR_MESSAGES['invalid_mnemonic_checksum'])

    return entropy_bytes


def generate_mnemonic(word_count: int = 12) -> str:
    """
    Generates a cryptographically secure mnemonic phrase.

    Args:
        word_count: The number of words in the mnemonic (e.g., 12, 15, 18, 21, 24).

    Returns:
        A space-separated mnemonic phrase string.
    """
    if word_count not in VALID_MNEMONIC_LENGTHS:
        raise ValueError(ERROR_MESSAGES['invalid_mnemonic_length'])

    mnemonic_list = [secrets.choice(BIP39_WORD_LIST) for _ in range(word_count)]

    return " ".join(mnemonic_list)


def validate_mnemonic(mnemonic: str) -> bool:
    """
    Validate a BIP39 mnemonic phrase.
    
    Args:
        mnemonic: The mnemonic phrase to validate.
        
    Returns:
        True if the mnemonic is valid, False otherwise.
    """
    try:
        _mnemonic_to_entropy(mnemonic)
        return True
    except InvalidMnemonicError:
        return False


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Convert a BIP39 mnemonic phrase to a seed using PBKDF2.
    
    Args:
        mnemonic: The mnemonic phrase.
        passphrase: Optional passphrase for additional security. Default is empty.
        
    Returns:
        A 64-byte seed that can be used to generate HD wallet keys.
        
    Raises:
        InvalidMnemonicError: If the mnemonic is invalid.
    """
    # Validate mnemonic first
    if not validate_mnemonic(mnemonic):
        raise InvalidMnemonicError("Invalid mnemonic phrase")

    # Normalize mnemonic (NFKD normalization)
    normalized_mnemonic = mnemonic.strip()

    # Use our internal BIP39 PBKDF2 implementation
    seed = bip39_pbkdf2(normalized_mnemonic, passphrase)

    return seed


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    """
    Convert a BIP39 mnemonic phrase back to its original entropy.
    
    Args:
        mnemonic: The mnemonic phrase.
        
    Returns:
        The original entropy bytes.
        
    Raises:
        InvalidMnemonicError: If the mnemonic is invalid.
    """
    return _mnemonic_to_entropy(mnemonic)


def entropy_to_mnemonic(entropy: Union[bytes, str]) -> str:
    """
    Convert entropy to a BIP39 mnemonic phrase.
    
    Args:
        entropy: Entropy as bytes or hex string (16, 20, 24, 28, or 32 bytes).
        
    Returns:
        A BIP39 mnemonic phrase string.
        
    Raises:
        InvalidEntropyError: If entropy is invalid.
        
    Example:
        >>> mnemonic = entropy_to_mnemonic(bytes(16))  # All zeros
        >>> print(mnemonic)
    """
    if isinstance(entropy, str):
        # Convert hex string to bytes
        try:
            entropy = bytes.fromhex(entropy)
        except ValueError as e:
            raise InvalidEntropyError(f"Invalid hex string: {e}") from e

    return _entropy_to_mnemonic(entropy)


# For backward compatibility with the old simple implementation
def generate_simple_mnemonic(count: int) -> str:
    """
    Generate a simple mnemonic (for backward compatibility).
    This does NOT follow BIP39 standard and should not be used.
    """
    if count not in VALID_MNEMONIC_LENGTHS:
        raise ValueError("Invalid word count. Must be 12, 15, 18, 21, or 24.")

    # Generate random indices using internal random generation
    random_bytes = get_random_bytes(count * 2)  # 2 bytes per word for 16-bit random value
    words = []
    for i in range(count):
        # Get 2 bytes and convert to index in BIP39_WORD_LIST range (0-2047)
        idx = (random_bytes[i * 2] << 8 | random_bytes[i * 2 + 1]) % len(BIP39_WORD_LIST)
        words.append(BIP39_WORD_LIST[idx])

    return " ".join(words)


# Main functions for easy access
__all__ = [
    'generate_mnemonic',
    'validate_mnemonic',
    'mnemonic_to_seed',
    'mnemonic_to_entropy',
    'entropy_to_mnemonic',
    'InvalidMnemonicError',
    'InvalidEntropyError'
]

# Example usage
# if __name__ == "__main__":
#     mnemonic = generate_mnemonic(12)
#     print(f"Generated mnemonic: {mnemonic}")
#     print(f"Is valid: {validate_mnemonic(mnemonic)}")
#     seed = mnemonic_to_seed(mnemonic, passphrase="test")
#     print(f"Seed: {seed.hex()}")
#     print(f"Entropy: {mnemonic_to_entropy(mnemonic).hex()}")
#     print(f"Entropy to mnemonic: {entropy_to_mnemonic(mnemonic_to_entropy(mnemonic))}")
#     print(f"Simple mnemonic: {generate_simple_mnemonic(12)}")
