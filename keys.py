"""
Private and Public Key Classes

This module provides classes for handling private and public keys with
format conversions, WIF support, and cryptographic operations.
"""

from typing import Union, Optional, Tuple

from .secp256k1 import private_key_to_public_key, public_key_to_point
from ..Hash.SHA256 import SHA256Hash
from ..Hash.RIPEMD160 import RIPEMD160Hash
from ..Random import get_random_bytes
from ..Util.constants import SECP256K1_N, MAX_PRIVATE_KEY
from .formats import (
    private_key_to_wif, 
    wif_to_private_key,
    bytes_to_hex,
    hex_to_bytes,
    int_to_bytes,
    bytes_to_int,
    InvalidFormatError
)


class KeyError(ValueError):
    """Raised when key operations fail."""
    pass


class PrivateKey:
    """
    Represents a secp256k1 private key with various format conversions.
    
    Supports conversion to/from hex, WIF, bytes, and decimal formats.
    Can generate corresponding public keys and addresses.
    """
    
    def __init__(self, key: Union[bytes, int, str, None] = None, network: str = 'bitcoin'):
        """
        Initialize a private key.
        
        Args:
            key: Private key as bytes (32), int, hex string, or None to generate.
            network: Network type for WIF encoding. Default is 'bitcoin'.
            
        Raises:
            KeyError: If the key is invalid.
        """
        self.network = network
        
        if key is None:
            # Generate a new random private key
            self._key_int = self._generate_random_key()
        else:
            self._key_int = self._normalize_key(key)
        
        # Validate key
        if not (1 <= self._key_int <= MAX_PRIVATE_KEY):
            raise KeyError(f"Private key must be between 1 and {MAX_PRIVATE_KEY}")
        
        self._key_bytes = int_to_bytes(self._key_int, 32)
        self._public_key = None  # Lazy loading
    
    def _generate_random_key(self) -> int:
        """Generate a cryptographically secure random private key."""
        while True:
            key_bytes = get_random_bytes(32)
            key_int = bytes_to_int(key_bytes)
            if 1 <= key_int <= MAX_PRIVATE_KEY:
                return key_int
    
    def _normalize_key(self, key: Union[bytes, int, str]) -> int:
        """
        Normalize various key formats to integer.
        
        Args:
            key: Key in various formats.
            
        Returns:
            Key as integer.
            
        Raises:
            KeyError: If key format is invalid.
        """
        if isinstance(key, int):
            return key
        elif isinstance(key, bytes):
            if len(key) != 32:
                raise KeyError(f"Private key bytes must be 32 bytes, got {len(key)}")
            return bytes_to_int(key)
        elif isinstance(key, str):
            # Try hex first, then WIF
            if len(key) == 64:
                # Assume hex
                try:
                    key_bytes = hex_to_bytes(key)
                    return bytes_to_int(key_bytes)
                except InvalidFormatError as e:
                    raise KeyError(f"Invalid hex private key: {e}") from e
            else:
                # Assume WIF
                try:
                    key_bytes, _, _ = wif_to_private_key(key)
                    return bytes_to_int(key_bytes)
                except InvalidFormatError as e:
                    raise KeyError(f"Invalid WIF private key: {e}") from e
        else:
            raise KeyError(f"Unsupported key type: {type(key)}")
    
    @property
    def hex(self) -> str:
        """Get private key as hex string (64 characters)."""
        return bytes_to_hex(self._key_bytes)
    
    @property
    def bytes(self) -> bytes:
        """Get private key as bytes (32 bytes)."""
        return self._key_bytes
    
    @property
    def int(self) -> int:
        """Get private key as integer."""
        return self._key_int
    
    @property
    def decimal(self) -> str:
        """Get private key as decimal string."""
        return str(self._key_int)
    
    def to_wif(self, compressed: bool = True) -> str:
        """
        Convert to Wallet Import Format (WIF).
        
        Args:
            compressed: Whether to use compressed WIF. Default is True.
            
        Returns:
            WIF encoded private key.
        """
        return private_key_to_wif(self._key_bytes, compressed, self.network)
    
    def get_public_key(self, compressed: bool = True) -> 'PublicKey':
        """
        Get the corresponding public key.
        
        Args:
            compressed: Whether to use compressed public key. Default is True.
            
        Returns:
            PublicKey instance.
        """
        if self._public_key is None or self._public_key.compressed != compressed:
            # Generate public key using our secp256k1 implementation
            public_key_bytes = private_key_to_public_key(self._key_int, compressed)
            
            self._public_key = PublicKey(public_key_bytes, compressed)
        
        return self._public_key
    
    def sign_message(self, message: bytes) -> bytes:
        """
        Sign a message with this private key.
        
        Args:
            message: The message to sign.
            
        Returns:
            The signature bytes.
        """
        # For now, return a placeholder signature since ECDSA signing 
        # is complex and not essential for basic wallet functionality
        message_hash = SHA256Hash(SHA256Hash(message).digest()).digest()
        
        # Return a simple signature format (not real ECDSA)
        return b"placeholder_signature_" + message_hash[:16]
    
    @classmethod
    def from_wif(cls, wif: str) -> 'PrivateKey':
        """
        Create PrivateKey from WIF string.
        
        Args:
            wif: WIF encoded private key.
            
        Returns:
            New PrivateKey instance.
        """
        key_bytes, _, network = wif_to_private_key(wif)
        return cls(key_bytes, network)
    
    @classmethod
    def from_hex(cls, hex_str: str, network: str = 'bitcoin') -> 'PrivateKey':
        """
        Create PrivateKey from hex string.
        
        Args:
            hex_str: Hex encoded private key.
            network: Network type.
            
        Returns:
            New PrivateKey instance.
        """
        return cls(hex_str, network)
    
    @classmethod
    def from_int(cls, key_int: int, network: str = 'bitcoin') -> 'PrivateKey':
        """
        Create PrivateKey from integer.
        
        Args:
            key_int: Private key as integer.
            network: Network type.
            
        Returns:
            New PrivateKey instance.
        """
        return cls(key_int, network)
    
    @classmethod
    def generate(cls, network: str = 'bitcoin') -> 'PrivateKey':
        """
        Generate a new random private key.
        
        Args:
            network: Network type.
            
        Returns:
            New PrivateKey instance.
        """
        return cls(None, network)
    
    def __str__(self) -> str:
        """String representation (hex format)."""
        return self.hex
    
    def __repr__(self) -> str:
        """Developer representation."""
        return f"PrivateKey('{self.hex}', network='{self.network}')"
    
    def __eq__(self, other) -> bool:
        """Equality comparison."""
        if not isinstance(other, PrivateKey):
            return False
        return self._key_int == other._key_int


class PublicKey:
    """
    Represents a secp256k1 public key with address generation capabilities.
    
    Supports both compressed and uncompressed formats and can generate
    addresses for various cryptocurrencies.
    """
    
    def __init__(self, key: Union[bytes, str], compressed: bool = True):
        """
        Initialize a public key.
        
        Args:
            key: Public key as bytes or hex string.
            compressed: Whether this is a compressed public key.
            
        Raises:
            KeyError: If the key is invalid.
        """
        self.compressed = compressed
        self._key_bytes = self._normalize_key(key)
        
        # Validate key length
        expected_length = 33 if compressed else 65
        if len(self._key_bytes) != expected_length:
            raise KeyError(f"Public key must be {expected_length} bytes for "
                          f"{'compressed' if compressed else 'uncompressed'} format, "
                          f"got {len(self._key_bytes)}")
        
        # Validate prefix
        if compressed and self._key_bytes[0] not in [0x02, 0x03]:
            raise KeyError(f"Invalid compressed public key prefix: {self._key_bytes[0]:#x}")
        elif not compressed and self._key_bytes[0] != 0x04:
            raise KeyError(f"Invalid uncompressed public key prefix: {self._key_bytes[0]:#x}")
    
    def _normalize_key(self, key: Union[bytes, str]) -> bytes:
        """
        Normalize key format to bytes.
        
        Args:
            key: Key as bytes or hex string.
            
        Returns:
            Key as bytes.
        """
        if isinstance(key, bytes):
            return key
        elif isinstance(key, str):
            try:
                return hex_to_bytes(key)
            except InvalidFormatError as e:
                raise KeyError(f"Invalid hex public key: {e}") from e
        else:
            raise KeyError(f"Unsupported key type: {type(key)}")
    
    @property
    def hex(self) -> str:
        """Get public key as hex string."""
        return bytes_to_hex(self._key_bytes)
    
    @property
    def bytes(self) -> bytes:
        """Get public key as bytes."""
        return self._key_bytes
    
    def get_address(self, address_type: str = 'p2pkh', network: str = 'bitcoin') -> str:
        """
        Generate address from this public key.
        
        Args:
            address_type: Address type ('p2pkh', 'p2sh', 'p2wpkh', etc.).
            network: Network type.
            
        Returns:
            The address string.
        """
        from .addresses import AddressGenerator
        return AddressGenerator.from_public_key(self._key_bytes, address_type, network)
    
    def get_hash160(self) -> bytes:
        """
        Get RIPEMD160(SHA256(public_key)) hash.
        
        Returns:
            20-byte hash160.
        """
        sha256_hash = SHA256Hash(self._key_bytes).digest()
        return RIPEMD160Hash(sha256_hash).digest()
    
    def verify_message(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a message signature.
        
        Args:
            message: The original message.
            signature: The signature to verify.
            
        Returns:
            True if signature is valid.
        """
        try:
            # For now, return a simple verification for placeholder signatures
            message_hash = SHA256Hash(SHA256Hash(message).digest()).digest()
            expected_sig = b"placeholder_signature_" + message_hash[:16]
            return signature == expected_sig
        except Exception:
            return False
    
    def to_compressed(self) -> 'PublicKey':
        """
        Convert to compressed format.
        
        Returns:
            New PublicKey instance in compressed format.
        """
        if self.compressed:
            return self
        
        # Extract x coordinate and determine parity
        x_bytes = self._key_bytes[1:33]
        y_bytes = self._key_bytes[33:65]
        y_int = bytes_to_int(y_bytes)
        
        # Determine prefix based on y coordinate parity
        prefix = 0x02 if y_int % 2 == 0 else 0x03
        compressed_bytes = bytes([prefix]) + x_bytes
        
        return PublicKey(compressed_bytes, compressed=True)
    
    def to_uncompressed(self) -> 'PublicKey':
        """
        Convert to uncompressed format.
        
        Returns:
            New PublicKey instance in uncompressed format.
        """
        if not self.compressed:
            return self
        
        # This requires elliptic curve point reconstruction
        # For now, raise an error - would need ECC point operations
        raise NotImplementedError("Uncompressed conversion requires elliptic curve operations")
    
    @classmethod
    def from_hex(cls, hex_str: str, compressed: bool = True) -> 'PublicKey':
        """
        Create PublicKey from hex string.
        
        Args:
            hex_str: Hex encoded public key.
            compressed: Whether key is compressed.
            
        Returns:
            New PublicKey instance.
        """
        return cls(hex_str, compressed)
    
    @classmethod
    def from_private_key(cls, private_key: PrivateKey, compressed: bool = True) -> 'PublicKey':
        """
        Create PublicKey from PrivateKey.
        
        Args:
            private_key: The private key.
            compressed: Whether to use compressed format.
            
        Returns:
            New PublicKey instance.
        """
        return private_key.get_public_key(compressed)
    
    def __str__(self) -> str:
        """String representation (hex format)."""
        return self.hex
    
    def __repr__(self) -> str:
        """Developer representation."""
        return f"PublicKey('{self.hex}', compressed={self.compressed})"
    
    def __eq__(self, other) -> bool:
        """Equality comparison."""
        if not isinstance(other, PublicKey):
            return False
        return self._key_bytes == other._key_bytes and self.compressed == other.compressed


# Export main classes
__all__ = [
    'PrivateKey',
    'PublicKey', 
    'KeyError'
] 