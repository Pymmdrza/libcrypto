"""
High-Level Wallet Interface

This module provides a simple, high-level interface for creating cryptocurrency
wallets from a single private key and generating addresses for various coins.
"""
from typing import Union, Dict, List
from .keys import PrivateKey, PublicKey
from .addresses import AddressGenerator, AddressError
from .constants import BIP44_COIN_TYPES

# Configuration for coins, especially for properties like required public key format.
COIN_CONFIG = {
    'ethereum': {'uncompressed_required': True, 'address_types': ['default']},
    'tron': {'uncompressed_required': True, 'address_types': ['default']},
    'ripple': {'uncompressed_required': False, 'address_types': ['default']},  # Prefers compressed
    'bitcoin': {'uncompressed_required': False, 'address_types': ['p2pkh', 'p2sh-p2wpkh', 'p2wpkh']},
    'litecoin': {'uncompressed_required': False, 'address_types': ['p2pkh', 'p2sh-p2wpkh', 'p2wpkh']},
    'dogecoin': {'uncompressed_required': False, 'address_types': ['p2pkh']},
    'dash': {'uncompressed_required': False, 'address_types': ['p2pkh']},
    'bitcoin_cash': {'uncompressed_required': False, 'address_types': ['p2pkh']},
    'testnet': {'uncompressed_required': False, 'address_types': ['p2pkh', 'p2sh-p2wpkh', 'p2wpkh']},
}


class Wallet:
    """
    A simple wallet class to manage a single private key and generate addresses.

    This class serves as a high-level, easy-to-use wrapper around the library's
    core functionalities. It is initialized with a single private key and can
    generate corresponding addresses for multiple supported cryptocurrencies.
    """

    def __init__(self, private_key: Union[str, bytes, int, PrivateKey]):
        """
        Initializes the wallet with a private key.

        Args:
            private_key: The private key in WIF, hex, bytes, integer format,
                         or as a PrivateKey object.
        """
        if isinstance(private_key, PrivateKey):
            self.private_key = private_key
        else:
            self.private_key = PrivateKey(private_key)

        self._public_key_compressed = self.private_key.get_public_key(compressed=True)
        self._public_key_uncompressed = self.private_key.get_public_key(compressed=False)

    def get_address(self, coin: str, address_type: str = 'p2pkh') -> str:
        """
        Generates a single address for a specific coin and address type.

        Args:
            coin (str): The name of the coin (e.g., 'bitcoin', 'ethereum').
            address_type (str, optional): The type of address to generate.
                For Bitcoin coins: 'p2pkh' (default), 'p2sh-p2wpkh', 'p2wpkh'.
                For Ethereum coins, this is ignored.

        Returns:
            str: The generated address string.

        Raises:
            ValueError: If the coin or address type is not supported.
            NotImplementedError: For coins requiring a different cryptographic curve (e.g., Ed25519).
        """
        coin = coin.lower()
        if coin not in COIN_CONFIG:
            # Check if it's a known coin but just not in the simple config
            if coin in BIP44_COIN_TYPES:
                raise ValueError(f"Coin '{coin}' is recognized but not configured for simple address generation.")
            raise ValueError(f"Unsupported coin: '{coin}'")

        config = COIN_CONFIG[coin]

        # Select the correct public key format
        public_key = self._public_key_uncompressed if config['uncompressed_required'] else self._public_key_compressed

        # For coins with a single address type, override the user's choice
        if len(config['address_types']) == 1 and config['address_types'][0] == 'default':
            addr_type = 'default'  # A generic type for coins like ETH, TRX
        else:
            if address_type not in config['address_types']:
                raise ValueError(f"Unsupported address type '{address_type}' for {coin}. "
                                 f"Available types: {config['address_types']}")
            addr_type = address_type

        try:
            # In AddressGenerator, 'default' type is handled internally for relevant networks
            # and `addr_type` is used for Bitcoin-style networks.
            effective_type_for_generator = 'default' if addr_type == 'default' else addr_type
            return AddressGenerator.from_public_key(public_key.bytes, effective_type_for_generator, coin)
        except AddressError as e:
            raise ValueError(f"Could not generate address for {coin}: {e}")

    def get_all_addresses(self, coin: str) -> Dict[str, str]:
        """
        Generates all supported address formats for a given coin.

        Args:
            coin (str): The name of the coin (e.g., 'bitcoin', 'ethereum').

        Returns:
            Dict[str, str]: A dictionary where keys are address types and
                            values are the corresponding addresses.
        """
        coin = coin.lower()
        if coin not in COIN_CONFIG:
            raise ValueError(f"Unsupported coin: '{coin}'")

        addresses = {}
        config = COIN_CONFIG[coin]

        for addr_type in config['address_types']:
            try:
                # Use the main get_address method to ensure consistent logic
                addresses[addr_type] = self.get_address(coin, addr_type)
            except (ValueError, NotImplementedError, AddressError) as e:
                addresses[addr_type] = f"Error: {e}"

        return addresses

    @classmethod
    def generate(cls) -> 'Wallet':
        """
        Creates a new Wallet instance with a newly generated private key.

        Returns:
            A new Wallet instance.
        """
        return cls(PrivateKey.generate())

    def __repr__(self) -> str:
        return f"Wallet(private_key='{self.private_key.hex}')"
