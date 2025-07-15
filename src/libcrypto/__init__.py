"""
LibCrypto Wallet Module

This module provides comprehensive cryptocurrency wallet functionality including:
- BIP32 Hierarchical Deterministic (HD) wallets
- Multi-currency address generation
- Key format conversions
- WIF (Wallet Import Format) support
"""
from .wallet import Wallet
from .bip32 import HDWallet, HDNode, BIP32Error
from .keys import PrivateKey, PublicKey, KeyError
from .mnemonic import (
    generate_mnemonic,
    validate_mnemonic,
    mnemonic_to_seed,
    mnemonic_to_entropy,
    entropy_to_mnemonic,
    InvalidMnemonicError,
    InvalidEntropyError
)
from .addresses import AddressGenerator, AddressError
from .formats import (
    private_key_to_wif,
    wif_to_private_key,
    base58_encode,
    base58_decode,
    bytes_to_hex,
    hex_to_bytes,
    InvalidFormatError
)

__version__ = "1.0.6"
__all__ = [
    # Library Version
    '__version__',

    # High-Level Wallet
    'Wallet',

    # HD Wallet
    'HDWallet',
    'HDNode',
    'BIP32Error',

    # Key classes
    'PrivateKey',
    'PublicKey',
    'KeyError',

    # Address generation
    'AddressGenerator',
    'AddressError',

    # Format conversions
    'private_key_to_wif',
    'wif_to_private_key',
    'base58_encode',
    'base58_decode',
    'bytes_to_hex',
    'hex_to_bytes',
    'InvalidFormatError',

    # Mnemonic functions
    'generate_mnemonic',
    'validate_mnemonic',
    'mnemonic_to_seed',
    'mnemonic_to_entropy',
    'entropy_to_mnemonic',
    'InvalidMnemonicError',
    'InvalidEntropyError'
]
