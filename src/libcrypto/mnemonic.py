"""
BIP39 Mnemonic Phrase Implementation

This module provides comprehensive BIP39 mnemonic phrase functionality including:
- Secure mnemonic generation with proper entropy
- Mnemonic validation with checksum verification
- Mnemonic to seed conversion with PBKDF2
- Conversion between entropy and mnemonic phrases
"""
from typing import Union
from .hash import sha256, bip39_pbkdf2, secure_random_bytes
from .constants import (
    BIP39_WORD_LIST,
    BIP39_ENTROPY_BITS,
    BIP39_CHECKSUM_BITS,
    VALID_MNEMONIC_LENGTHS,
    ERROR_MESSAGES
)


class InvalidMnemonicError(ValueError):
    """Raised when a mnemonic phrase is invalid."""
    pass


class InvalidEntropyError(ValueError):
    """Raised when entropy is invalid."""
    pass


def _entropy_to_mnemonic_bits(entropy: bytes) -> str:
    """Internal helper to convert entropy to its bit representation with checksum."""
    entropy_bits_len = len(entropy) * 8
    if entropy_bits_len not in BIP39_ENTROPY_BITS.values():
        raise InvalidEntropyError(f"Invalid entropy length: {len(entropy)} bytes")

    checksum_len = BIP39_CHECKSUM_BITS[entropy_bits_len // 32 * 3]

    # Calculate checksum
    checksum_hash = sha256(entropy)
    checksum_bits = bin(checksum_hash[0])[2:].zfill(8)[:checksum_len]

    # Combine entropy and checksum
    entropy_bits = bin(int.from_bytes(entropy, 'big'))[2:].zfill(entropy_bits_len)

    return entropy_bits + checksum_bits


def entropy_to_mnemonic(entropy: Union[bytes, str]) -> str:
    """
    Convert entropy to a BIP39 mnemonic phrase.
    """
    if isinstance(entropy, str):
        try:
            entropy = bytes.fromhex(entropy)
        except ValueError as e:
            raise InvalidEntropyError(f"Invalid hex string for entropy: {e}") from e

    total_bits = _entropy_to_mnemonic_bits(entropy)

    # Split into 11-bit chunks and map to words
    words = []
    for i in range(0, len(total_bits), 11):
        chunk = total_bits[i:i + 11]
        word_index = int(chunk, 2)
        words.append(BIP39_WORD_LIST[word_index])

    return ' '.join(words)


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    """
    Convert a BIP39 mnemonic phrase back to its original entropy.
    """
    words = mnemonic.strip().split()
    word_count = len(words)

    if word_count not in VALID_MNEMONIC_LENGTHS:
        raise InvalidMnemonicError(ERROR_MESSAGES['invalid_mnemonic_length'])

    # Convert words to a bit string
    bit_string = ""
    for word in words:
        try:
            index = BIP39_WORD_LIST.index(word)
            bit_string += bin(index)[2:].zfill(11)
        except ValueError:
            raise InvalidMnemonicError(f"{ERROR_MESSAGES['invalid_mnemonic_word']}: '{word}'")

    # Split data and checksum
    entropy_len = BIP39_ENTROPY_BITS[word_count]
    checksum_len = BIP39_CHECKSUM_BITS[word_count]

    entropy_bits = bit_string[:entropy_len]
    checksum_bits = bit_string[entropy_len:]

    # Convert entropy bits to bytes
    entropy_bytes = int(entropy_bits, 2).to_bytes(entropy_len // 8, 'big')

    # Verify checksum
    expected_checksum_hash = sha256(entropy_bytes)
    expected_checksum = bin(expected_checksum_hash[0])[2:].zfill(8)[:checksum_len]

    if checksum_bits != expected_checksum:
        raise InvalidMnemonicError(ERROR_MESSAGES['invalid_mnemonic_checksum'])

    return entropy_bytes


def generate_mnemonic(word_count: int = 12) -> str:
    """
    Generates a cryptographically secure mnemonic phrase.
    """
    if word_count not in VALID_MNEMONIC_LENGTHS:
        raise ValueError(ERROR_MESSAGES['invalid_mnemonic_length'])

    entropy_bits = BIP39_ENTROPY_BITS[word_count]
    entropy = secure_random_bytes(entropy_bits // 8)

    return entropy_to_mnemonic(entropy)


def validate_mnemonic(mnemonic: str) -> bool:
    """
    Validate a BIP39 mnemonic phrase by trying to convert it to entropy.
    """
    try:
        mnemonic_to_entropy(mnemonic)
        return True
    except InvalidMnemonicError:
        return False


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Convert a BIP39 mnemonic phrase to a seed using PBKDF2.
    """
    # NFKD normalization is recommended by BIP39 spec
    import unicodedata
    normalized_mnemonic = unicodedata.normalize('NFKD', mnemonic.strip())

    if not validate_mnemonic(normalized_mnemonic):
        raise InvalidMnemonicError("Invalid mnemonic phrase provided.")

    return bip39_pbkdf2(normalized_mnemonic, passphrase)


__all__ = [
    'generate_mnemonic',
    'validate_mnemonic',
    'mnemonic_to_seed',
    'mnemonic_to_entropy',
    'entropy_to_mnemonic',
    'InvalidMnemonicError',
    'InvalidEntropyError'
]
