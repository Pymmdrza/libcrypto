"""
BIP39 Mnemonic Phrase Implementation

This module provides complete BIP39 functionality for generating, validating,
and converting mnemonic phrases to seeds for cryptocurrency wallets.

BIP39 Standard: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
"""

import os
from typing import List, Optional, Union
import secrets
from ..Hash import SHA256, SHA512
from ..Protocol.KDF import PBKDF2
from ..Random import get_random_bytes
from ..Util.constants import (
    BIP39_WORD_LIST,
    BIP39_ENTROPY_BITS,
    BIP39_CHECKSUM_BITS,
    VALID_MNEMONIC_LENGTHS,
    PBKDF2_ITERATIONS,
    PBKDF2_HMAC_DKLEN,
    ERROR_MESSAGES
)


class BIP39Error(ValueError):
    """Exception raised for BIP39-related errors."""
    pass


def _pbkdf2_hmac_sha512(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    """
    Internal PBKDF2 implementation using internal HMAC-SHA512.
    
    Args:
        password: Password bytes
        salt: Salt bytes  
        iterations: Number of iterations
        dklen: Desired key length in bytes
        
    Returns:
        Derived key bytes
    """
    # Use internal PBKDF2 implementation with SHA512
    return PBKDF2(password, salt, dklen, iterations, hmac_hash_module=SHA512)


def _entropy_to_mnemonic(entropy: bytes) -> str:
    """
    Convert entropy bytes to mnemonic phrase.
    
    Args:
        entropy: Random entropy bytes
        
    Returns:
        Mnemonic phrase as string
        
    Raises:
        BIP39Error: If entropy length is invalid
    """
    if len(entropy) not in [16, 20, 24, 28, 32]:  # 128, 160, 192, 224, 256 bits
        raise BIP39Error(f"Invalid entropy length: {len(entropy)} bytes")

    # Calculate checksum using internal SHA256
    checksum = SHA256.new(entropy).digest()
    checksum_bits = len(entropy) // 4  # 1 bit per 4 bytes of entropy

    # Convert entropy to binary string
    entropy_bin = ''.join(f'{byte:08b}' for byte in entropy)

    # Add checksum bits
    checksum_bin = ''.join(f'{byte:08b}' for byte in checksum)
    entropy_bin += checksum_bin[:checksum_bits]

    # Split into 11-bit groups and convert to word indices
    words = []
    for i in range(0, len(entropy_bin), 11):
        word_index = int(entropy_bin[i:i + 11], 2)
        words.append(BIP39_WORD_LIST[word_index])

    return ' '.join(words)


def _mnemonic_to_entropy(mnemonic: str) -> bytes:
    """
    Convert mnemonic phrase to entropy bytes.
    
    Args:
        mnemonic: Mnemonic phrase
        
    Returns:
        Entropy bytes
        
    Raises:
        BIP39Error: If mnemonic is invalid
    """
    words = mnemonic.strip().split()

    if len(words) not in VALID_MNEMONIC_LENGTHS:
        raise BIP39Error(f"Invalid mnemonic length: {len(words)} words")

    # Convert words to indices
    try:
        indices = [BIP39_WORD_LIST.index(word) for word in words]
    except ValueError as e:
        raise BIP39Error(f"Invalid word in mnemonic: {e}")

    # Convert indices to binary
    binary_str = ''.join(f'{index:011b}' for index in indices)

    # Split entropy and checksum
    entropy_bits = len(words) * 11 * 32 // 33  # Remove checksum bits
    checksum_bits = len(binary_str) - entropy_bits

    entropy_bin = binary_str[:entropy_bits]
    checksum_bin = binary_str[entropy_bits:]

    # Convert entropy binary to bytes
    entropy_bytes = bytes(int(entropy_bin[i:i + 8], 2) for i in range(0, len(entropy_bin), 8))

    # Verify checksum using internal SHA256
    expected_checksum = SHA256.new(entropy_bytes).digest()
    expected_checksum_bin = ''.join(f'{byte:08b}' for byte in expected_checksum)[:checksum_bits]

    if checksum_bin != expected_checksum_bin:
        raise BIP39Error("Invalid mnemonic checksum")

    return entropy_bytes


def generate_mnemonic(word_count: int = 12) -> str:
    """
    Generate a new BIP39 mnemonic phrase.
    
    Args:
        word_count: Number of words in mnemonic (12, 15, 18, 21, or 24)
        
    Returns:
        Generated mnemonic phrase
        
    Raises:
        BIP39Error: If word count is invalid
    """
    if word_count not in VALID_MNEMONIC_LENGTHS:
        raise ValueError(ERROR_MESSAGES['invalid_mnemonic_length'])

    mnemonic_list = [secrets.choice(BIP39_WORD_LIST) for _ in range(word_count)]

    return " ".join(mnemonic_list)


def validate_mnemonic(mnemonic: str) -> bool:
    """
    Validate a BIP39 mnemonic phrase.
    
    Args:
        mnemonic: Mnemonic phrase to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        _mnemonic_to_entropy(mnemonic)
        return True
    except BIP39Error:
        return False


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Convert mnemonic phrase to seed bytes using PBKDF2.
    
    Args:
        mnemonic: BIP39 mnemonic phrase
        passphrase: Optional passphrase for additional security
        
    Returns:
        64-byte seed
        
    Raises:
        BIP39Error: If mnemonic is invalid
    """
    if not validate_mnemonic(mnemonic):
        raise BIP39Error("Invalid mnemonic phrase")

    # Normalize mnemonic (preserve case as per BIP39 standard)
    mnemonic_normalized = mnemonic.strip()

    # Create salt
    salt = ("mnemonic" + passphrase).encode('utf-8')

    # Generate seed using PBKDF2
    seed = _pbkdf2_hmac_sha512(
        password=mnemonic_normalized.encode('utf-8'),
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        dklen=PBKDF2_HMAC_DKLEN
    )

    return seed


def get_word_list() -> tuple:
    """
    Get the BIP39 word list.
    
    Returns:
        Tuple of 2048 BIP39 words
    """
    return BIP39_WORD_LIST


def is_valid_word(word: str) -> bool:
    """
    Check if a word is in the BIP39 word list.
    
    Args:
        word: Word to check
        
    Returns:
        True if word is valid, False otherwise
    """
    return word.lower() in BIP39_WORD_LIST


def get_word_suggestions(partial_word: str, limit: int = 10) -> List[str]:
    """
    Get word suggestions for partial word input.
    
    Args:
        partial_word: Partial word to match
        limit: Maximum number of suggestions
        
    Returns:
        List of matching words
    """
    partial_lower = partial_word.lower()
    suggestions = [word for word in BIP39_WORD_LIST if word.startswith(partial_lower)]
    return suggestions[:limit]


# Export main functions
__all__ = [
    'generate_mnemonic',
    'validate_mnemonic',
    'mnemonic_to_seed',
    'get_word_list',
    'is_valid_word',
    'get_word_suggestions',
    'BIP39Error'
]
