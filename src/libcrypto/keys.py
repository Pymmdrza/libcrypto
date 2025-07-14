"""
Private and Public Key Classes

This module provides classes for handling private and public keys with
format conversions, WIF support, and cryptographic operations.
"""
from typing import Union
from .secp256k1 import (
    private_key_to_public_key, compress_public_key, decompress_public_key
)
from .hash import secure_random_bytes
from .constants import MAX_PRIVATE_KEY
from .formats import (
    private_key_to_wif, wif_to_private_key, bytes_to_hex, hex_to_bytes,
    int_to_bytes, bytes_to_int, InvalidFormatError
)
from .addresses import AddressGenerator


class KeyError(ValueError):
    """Raised when key operations fail."""
    pass


class PrivateKey:
    """
    Represents a secp256k1 private key.
    """

    def __init__(self, key: Union[bytes, int, str, None] = None, network: str = 'bitcoin'):
        self.network = network
        if key is None:
            self._key_int = self._generate_random_key()
        else:
            self._key_int = self._normalize_key(key)

        if not (1 <= self._key_int <= MAX_PRIVATE_KEY):
            raise KeyError(f"Private key is out of valid range (1 to N-1).")

        self._key_bytes = int_to_bytes(self._key_int, 32)
        self._public_key_cache = {}

    @staticmethod
    def _generate_random_key() -> int:
        """Generate a cryptographically secure random private key."""
        while True:
            key_bytes = secure_random_bytes(32)
            key_int = bytes_to_int(key_bytes)
            if 1 <= key_int <= MAX_PRIVATE_KEY:
                return key_int

    def _normalize_key(self, key: Union[bytes, int, str]) -> int:
        """Normalize various key formats to an integer."""
        if isinstance(key, int):
            return key
        if isinstance(key, bytes):
            if len(key) != 32:
                raise KeyError(f"Private key bytes must be 32 bytes, got {len(key)}")
            return bytes_to_int(key)
        if isinstance(key, str):
            try:
                # First, try to decode as WIF
                key_bytes, _, _ = wif_to_private_key(key)
                self.network = _[2]  # Update network from WIF
                return bytes_to_int(key_bytes)
            except InvalidFormatError:
                # If WIF fails, try to decode as hex
                try:
                    if len(key) != 64:
                        raise InvalidFormatError("Hex key must be 64 characters.")
                    key_bytes = hex_to_bytes(key)
                    return bytes_to_int(key_bytes)
                except InvalidFormatError as e:
                    raise KeyError(f"Invalid private key format. Not valid WIF or Hex: {e}") from e
        raise KeyError(f"Unsupported key type: {type(key)}")

    @property
    def hex(self) -> str:
        return bytes_to_hex(self._key_bytes)

    @property
    def bytes(self) -> bytes:
        return self._key_bytes

    @property
    def int(self) -> int:
        return self._key_int

    def to_wif(self, compressed: bool = True) -> str:
        return private_key_to_wif(self._key_bytes, compressed, self.network)

    def get_public_key(self, compressed: bool = True) -> 'PublicKey':
        """Get the corresponding public key, using a cache for efficiency."""
        if compressed not in self._public_key_cache:
            public_key_bytes = private_key_to_public_key(self._key_int, compressed)
            self._public_key_cache[compressed] = PublicKey(public_key_bytes)
        return self._public_key_cache[compressed]

    @classmethod
    def generate(cls, network: str = 'bitcoin') -> 'PrivateKey':
        """Generate a new random private key."""
        return cls(None, network)

    def __repr__(self) -> str:
        return f"PrivateKey(network='{self.network}')"


class PublicKey:
    """
    Represents a secp256k1 public key.
    """

    def __init__(self, key: Union[bytes, str]):
        if isinstance(key, str):
            key = hex_to_bytes(key)

        if len(key) not in [33, 65]:
            raise KeyError(f"Invalid public key length: {len(key)}. Must be 33 or 65 bytes.")

        self._key_bytes = key
        self.compressed = (len(key) == 33)

    @property
    def hex(self) -> str:
        return bytes_to_hex(self._key_bytes)

    @property
    def bytes(self) -> bytes:
        return self._key_bytes

    def get_address(self, address_type: str = 'p2pkh', network: str = 'bitcoin') -> str:
        """
        Generate an address from this public key.
        This is a method, not a property, as it requires arguments.
        """
        return AddressGenerator.from_public_key(self.bytes, address_type, network)

    def to_compressed(self) -> 'PublicKey':
        if self.compressed:
            return self
        return PublicKey(compress_public_key(self.bytes))

    def to_uncompressed(self) -> 'PublicKey':
        if not self.compressed:
            return self
        return PublicKey(decompress_public_key(self.bytes))

    def __repr__(self) -> str:
        return f"PublicKey('{self.hex}', compressed={self.compressed})"
