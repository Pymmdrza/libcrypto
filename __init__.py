"""
LibCrypto - A comprehensive cryptocurrency wallet library.

This library provides a complete toolkit for cryptocurrency wallet operations including:
- BIP39 mnemonic phrase generation and validation
- BIP32 hierarchical deterministic wallet derivation
- Multi-currency address generation (Bitcoin, Ethereum, Litecoin, etc.)
- Cryptographic primitives and utilities

Features:
- Zero external dependencies
- High-performance C extensions for critical operations
- Type hints for better development experience
- Comprehensive test coverage

Supported Cryptocurrencies:
- Bitcoin (BTC) - P2PKH, P2SH, P2WPKH, P2WSH
- Ethereum (ETH)
- Litecoin (LTC)
- Dash (DASH)
- Dogecoin (DOGE)
- Bitcoin Cash (BCH)
- And many more...
"""

__version__ = "1.0.0"
__author__ = "LibCrypto Team"
__email__ = "info@libcrypto.dev"
__license__ = "MIT"

# Core imports - handle both relative and absolute imports
try:
    # Try relative imports first (when imported as a package)
    from . import wallet
    from . import Core
    from . import Hash
    from . import Util
    from . import Cipher
    from . import Signature
    from . import PublicKey
    from . import Random
    from . import Protocol
    from . import Math
    from . import IO
    from . import bip39
except ImportError:
    # Fall back to absolute imports (when running as a script)
    import wallet
    import Core
    import Hash
    import Util
    import Cipher
    import Signature
    import PublicKey
    import Random
    import Protocol
    import Math
    import IO
    import bip39

# Main wallet functionality - import from the correct modules
try:
    # Try relative imports first (when imported as a package)
    from .bip39 import (
        generate_mnemonic,
        validate_mnemonic,
        mnemonic_to_seed
    )
    
    from .wallet import (
        HDWallet,
        HDNode,
        PrivateKey,
        PublicKey as WalletPublicKey,
        AddressGenerator
    )
except ImportError:
    # Fall back to absolute imports (when running as a script)
    from bip39 import (
        generate_mnemonic,
        validate_mnemonic,
        mnemonic_to_seed
    )
    
    from wallet import (
        HDWallet,
        HDNode,
        PrivateKey,
        PublicKey as WalletPublicKey,
        AddressGenerator
    )

# Convenience functions for common operations
def create_hd_wallet(mnemonic: str, passphrase: str = "", network: str = 'mainnet') -> 'wallet.HDWallet':
    """
    Create an HD wallet from a mnemonic phrase.
    
    Args:
        mnemonic: BIP39 mnemonic phrase.
        passphrase: Optional passphrase.
        network: Network type ('mainnet' or 'testnet').
        
    Returns:
        HDWallet instance.
    """
    return wallet.HDWallet.from_mnemonic(mnemonic, passphrase, network)

def generate_address(currency: str, mnemonic: str, passphrase: str = "", 
                    account: int = 0, change: int = 0, address_index: int = 0) -> str:
    """
    Generate a cryptocurrency address from mnemonic.
    
    Args:
        currency: Currency symbol (btc, eth, ltc, etc.).
        mnemonic: BIP39 mnemonic phrase.
        passphrase: Optional passphrase.
        account: Account number.
        change: Change flag (0 for external, 1 for internal).
        address_index: Address index.
        
    Returns:
        Cryptocurrency address string.
    """
    wallet_instance = create_hd_wallet(mnemonic, passphrase)
    from .Util.constants import BIP44_COIN_TYPES
    
    if currency not in BIP44_COIN_TYPES:
        raise ValueError(f"Unsupported currency: {currency}")
    
    coin_type = BIP44_COIN_TYPES[currency]
    key_node = wallet_instance.derive_address_key(coin_type, account, change, address_index)
    
    # Generate address using the address generator
    address_gen = wallet.AddressGenerator()
    return address_gen.generate_address(key_node.private_key, currency)

def get_private_key(mnemonic: str, passphrase: str = "", 
                   coin_type: int = 0, account: int = 0, 
                   change: int = 0, address_index: int = 0) -> str:
    """
    Get private key from mnemonic using BIP44 derivation.
    
    Args:
        mnemonic: BIP39 mnemonic phrase.
        passphrase: Optional passphrase.
        coin_type: BIP44 coin type.
        account: Account number.
        change: Change flag.
        address_index: Address index.
        
    Returns:
        Private key as hex string.
    """
    wallet_instance = create_hd_wallet(mnemonic, passphrase)
    key_node = wallet_instance.derive_address_key(coin_type, account, change, address_index)
    return key_node.private_key.hex()

def get_public_key(mnemonic: str, passphrase: str = "", 
                  coin_type: int = 0, account: int = 0, 
                  change: int = 0, address_index: int = 0) -> str:
    """
    Get public key from mnemonic using BIP44 derivation.
    
    Args:
        mnemonic: BIP39 mnemonic phrase.
        passphrase: Optional passphrase.
        coin_type: BIP44 coin type.
        account: Account number.
        change: Change flag.
        address_index: Address index.
        
    Returns:
        Public key as hex string.
    """
    wallet_instance = create_hd_wallet(mnemonic, passphrase)
    key_node = wallet_instance.derive_address_key(coin_type, account, change, address_index)
    return key_node.public_key.hex()

# Supported currencies
SUPPORTED_CURRENCIES = [
    'btc', 'eth', 'ltc', 'dash', 'doge', 'bch', 'btg', 
    'dgb', 'sol', 'avax', 'ton', 'zec', 'xrp', 'trx'
]

# Constants
BIP39_WORD_COUNT_OPTIONS = [12, 15, 18, 21, 24]
DEFAULT_DERIVATION_PATH = "m/44'/0'/0'/0/0"

__all__ = [
    # Version info
    '__version__',
    '__author__',
    '__email__',
    '__license__',
    
    # Modules
    'wallet',
    'Core',
    'Hash',
    'Util',
    'Cipher',
    'Signature',
    'PublicKey',
    'Random',
    'Protocol',
    'Math',
    'IO',
    'bip39',
    
    # BIP39 functions
    'generate_mnemonic',
    'validate_mnemonic', 
    'mnemonic_to_seed',
    
    # Wallet classes
    'HDWallet',
    'HDNode',
    'PrivateKey',
    'WalletPublicKey',
    'AddressGenerator',
    
    # Convenience functions
    'create_hd_wallet',
    'generate_address',
    'get_private_key',
    'get_public_key',
    
    # Constants
    'SUPPORTED_CURRENCIES',
    'BIP39_WORD_COUNT_OPTIONS',
    'DEFAULT_DERIVATION_PATH'
]

def get_version():
    """Get the current version of LibCrypto."""
    return __version__

def get_supported_currencies():
    """Get list of supported cryptocurrency symbols."""
    return SUPPORTED_CURRENCIES.copy()

def info():
    """Print information about LibCrypto."""
    print(f"LibCrypto v{__version__}")
    print(f"Supported currencies: {', '.join(SUPPORTED_CURRENCIES)}")
    print(f"BIP39 word counts: {BIP39_WORD_COUNT_OPTIONS}")
    print(f"Default derivation path: {DEFAULT_DERIVATION_PATH}")
