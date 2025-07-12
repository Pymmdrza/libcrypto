"""
BIP32 Hierarchical Deterministic (HD) Wallet Implementation

This module provides BIP32 compliant hierarchical deterministic wallet functionality
including master key generation from seed, child key derivation, and extended key
serialization (xprv/xpub format).
"""

import struct
from typing import Union, Optional, List, Tuple

from ..Hash.SHA256 import SHA256Hash
from ..Hash.RIPEMD160 import RIPEMD160Hash
from ..PublicKey.ECC import EccKey
from ..Math.Numbers import Integer
from ..Util.constants import (
    BIP32_HARDENED_OFFSET,
    BIP32_HMAC_KEY,
    XPRV_MAINNET,
    XPUB_MAINNET,
    XPRV_TESTNET,
    XPUB_TESTNET,
    SECP256K1_N,
    MAX_BIP32_INDEX
)
from .formats import base58_check_encode, base58_check_decode, InvalidFormatError
from .crypto_utils import hmac_sha512
from .secp256k1 import private_key_to_public_key


class BIP32Error(ValueError):
    """Raised when BIP32 operations fail."""
    pass


class HDNode:
    """
    A single node in a BIP32 hierarchical deterministic wallet tree.
    
    Represents either a private or public key with associated chain code,
    depth, parent fingerprint, and child number.
    """
    
    def __init__(self, 
                 private_key: Optional[bytes] = None,
                 public_key: Optional[bytes] = None,
                 chain_code: bytes = b'',
                 depth: int = 0,
                 parent_fingerprint: bytes = b'\x00\x00\x00\x00',
                 child_number: int = 0,
                 network: str = 'mainnet'):
        """
        Initialize an HD node.
        
        Args:
            private_key: 32-byte private key (optional).
            public_key: 33-byte compressed public key (optional).
            chain_code: 32-byte chain code.
            depth: Derivation depth (0 for master).
            parent_fingerprint: 4-byte parent key fingerprint.
            child_number: Child key index.
            network: Network type ('mainnet' or 'testnet').
            
        Raises:
            BIP32Error: If both or neither private_key and public_key are provided.
        """
        if (private_key is None) == (public_key is None):
            raise BIP32Error("Exactly one of private_key or public_key must be provided")
        
        if len(chain_code) != 32:
            raise BIP32Error(f"Chain code must be 32 bytes, got {len(chain_code)}")
        
        if depth < 0 or depth > 255:
            raise BIP32Error(f"Depth must be between 0 and 255, got {depth}")
        
        if len(parent_fingerprint) != 4:
            raise BIP32Error(f"Parent fingerprint must be 4 bytes, got {len(parent_fingerprint)}")
        
        if child_number < 0 or child_number > 0xFFFFFFFF:
            raise BIP32Error(f"Child number must be between 0 and 2^32-1, got {child_number}")
        
        self._private_key = private_key
        self._public_key = public_key
        self.chain_code = chain_code
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.child_number = child_number
        self.network = network
        
        # Generate missing key from the provided one
        if private_key is not None:
            self._derive_public_from_private()
        
    def _derive_public_from_private(self) -> None:
        """Derive the public key from the private key using secp256k1."""
        if self._private_key is None:
            raise BIP32Error("No private key available")
        
        # Convert private key to public key using our secp256k1 implementation
        private_int = int.from_bytes(self._private_key, byteorder='big')
        
        # Get compressed public key (33 bytes: 0x02/0x03 + 32-byte x coordinate)
        self._public_key = private_key_to_public_key(private_int, compressed=True)
    
    @property
    def private_key(self) -> Optional[bytes]:
        """Get the private key bytes (32 bytes)."""
        return self._private_key
    
    @property
    def public_key(self) -> bytes:
        """Get the compressed public key bytes (33 bytes)."""
        if self._public_key is None:
            raise BIP32Error("No public key available")
        return self._public_key
    
    @property
    def is_private(self) -> bool:
        """Check if this node contains a private key."""
        return self._private_key is not None
    
    @property
    def fingerprint(self) -> bytes:
        """Get the 4-byte fingerprint of this key."""
        # Fingerprint is first 4 bytes of RIPEMD160(SHA256(public_key))
        sha256_hash = SHA256Hash(self.public_key).digest()
        ripemd160_hash = RIPEMD160Hash(sha256_hash).digest()
        return ripemd160_hash[:4]
    
    def derive_child(self, index: int) -> 'HDNode':
        """
        Derive a child key at the given index.
        
        Args:
            index: Child index (0 to 2^31-1 for normal, 2^31 to 2^32-1 for hardened).
            
        Returns:
            A new HDNode representing the child key.
            
        Raises:
            BIP32Error: If derivation fails or index is invalid.
        """
        if index < 0 or index > 0xFFFFFFFF:
            raise BIP32Error(f"Child index must be between 0 and 2^32-1, got {index}")
        
        is_hardened = index >= BIP32_HARDENED_OFFSET
        
        # For hardened derivation, we need the private key
        if is_hardened and not self.is_private:
            raise BIP32Error("Cannot derive hardened child from public key only")
        
        # Prepare data for HMAC
        if is_hardened:
            # Hardened: 0x00 + private_key + index
            data = b'\x00' + self._private_key + struct.pack('>I', index)
        else:
            # Normal: public_key + index
            data = self.public_key + struct.pack('>I', index)
        
        # Compute HMAC-SHA512
        hmac_result = hmac_sha512(self.chain_code, data)
        
        # Split result
        child_private_bytes = hmac_result[:32]
        child_chain_code = hmac_result[32:]
        
        # Parse private key as integer
        child_private_int = int.from_bytes(child_private_bytes, byteorder='big')
        
        # Check validity
        if child_private_int == 0 or child_private_int >= SECP256K1_N:
            # Invalid key, try next index (this is extremely rare)
            return self.derive_child(index + 1)
        
        if self.is_private:
            # Derive private child
            parent_private_int = int.from_bytes(self._private_key, byteorder='big')
            child_private_final = (child_private_int + parent_private_int) % SECP256K1_N
            
            if child_private_final == 0:
                # Invalid key, try next index
                return self.derive_child(index + 1)
            
            child_private_key = child_private_final.to_bytes(32, byteorder='big')
            child_public_key = None
        else:
            # Derive public child (normal derivation only)
            # This is more complex and requires point addition on the curve
            # For now, we'll require private keys for derivation
            raise BIP32Error("Public key derivation not yet implemented")
        
        return HDNode(
            private_key=child_private_key,
            public_key=child_public_key,
            chain_code=child_chain_code,
            depth=self.depth + 1,
            parent_fingerprint=self.fingerprint,
            child_number=index,
            network=self.network
        )
    
    def derive_path(self, path: str) -> 'HDNode':
        """
        Derive a key using a derivation path string.
        
        Args:
            path: Derivation path like "m/44'/0'/0'/0/0" or "44'/0'/0'/0/0".
            
        Returns:
            A new HDNode at the specified path.
            
        Raises:
            BIP32Error: If path is invalid.
        """
        if path.startswith('m/'):
            path = path[2:]
        elif path.startswith('/'):
            path = path[1:]
        
        if not path:
            return self
        
        node = self
        for segment in path.split('/'):
            if not segment:
                continue
            
            # Parse hardened notation
            if segment.endswith("'") or segment.endswith('h'):
                index = int(segment[:-1]) + BIP32_HARDENED_OFFSET
            else:
                index = int(segment)
            
            node = node.derive_child(index)
        
        return node
    
    def serialize_private(self) -> str:
        """
        Serialize this node as an extended private key (xprv).
        
        Returns:
            Base58Check encoded extended private key.
            
        Raises:
            BIP32Error: If this node doesn't have a private key.
        """
        if not self.is_private:
            raise BIP32Error("Cannot serialize private key - node is public only")
        
        # Version bytes
        if self.network == 'mainnet':
            version = XPRV_MAINNET
        else:
            version = XPRV_TESTNET
        
        # Serialize components
        payload = (
            struct.pack('>I', version) +                    # 4 bytes: version
            struct.pack('B', self.depth) +                  # 1 byte: depth
            self.parent_fingerprint +                       # 4 bytes: parent fingerprint
            struct.pack('>I', self.child_number) +          # 4 bytes: child number
            self.chain_code +                               # 32 bytes: chain code
            b'\x00' + self._private_key                     # 33 bytes: 0x00 + private key
        )
        
        return base58_check_encode(payload)
    
    def serialize_public(self) -> str:
        """
        Serialize this node as an extended public key (xpub).
        
        Returns:
            Base58Check encoded extended public key.
        """
        # Version bytes
        if self.network == 'mainnet':
            version = XPUB_MAINNET
        else:
            version = XPUB_TESTNET
        
        # Serialize components
        payload = (
            struct.pack('>I', version) +                    # 4 bytes: version
            struct.pack('B', self.depth) +                  # 1 byte: depth
            self.parent_fingerprint +                       # 4 bytes: parent fingerprint
            struct.pack('>I', self.child_number) +          # 4 bytes: child number
            self.chain_code +                               # 32 bytes: chain code
            self.public_key                                 # 33 bytes: compressed public key
        )
        
        return base58_check_encode(payload)
    
    @classmethod
    def deserialize(cls, extended_key: str) -> 'HDNode':
        """
        Deserialize an extended key (xprv/xpub) into an HDNode.
        
        Args:
            extended_key: Base58Check encoded extended key.
            
        Returns:
            A new HDNode instance.
            
        Raises:
            BIP32Error: If deserialization fails.
        """
        try:
            payload = base58_check_decode(extended_key)
        except InvalidFormatError as e:
            raise BIP32Error(f"Invalid extended key format: {e}") from e
        
        if len(payload) != 78:
            raise BIP32Error(f"Invalid extended key length: {len(payload)}")
        
        # Parse components
        version = struct.unpack('>I', payload[0:4])[0]
        depth = payload[4]
        parent_fingerprint = payload[5:9]
        child_number = struct.unpack('>I', payload[9:13])[0]
        chain_code = payload[13:45]
        key_data = payload[45:78]
        
        # Determine network and key type
        if version in [XPRV_MAINNET, XPRV_TESTNET]:
            # Private key
            if key_data[0] != 0x00:
                raise BIP32Error("Invalid private key prefix")
            private_key = key_data[1:]
            public_key = None
            network = 'mainnet' if version == XPRV_MAINNET else 'testnet'
        elif version in [XPUB_MAINNET, XPUB_TESTNET]:
            # Public key
            private_key = None
            public_key = key_data
            network = 'mainnet' if version == XPUB_MAINNET else 'testnet'
        else:
            raise BIP32Error(f"Unknown extended key version: {version}")
        
        return cls(
            private_key=private_key,
            public_key=public_key,
            chain_code=chain_code,
            depth=depth,
            parent_fingerprint=parent_fingerprint,
            child_number=child_number,
            network=network
        )


class HDWallet:
    """
    BIP32 Hierarchical Deterministic Wallet.
    
    Provides high-level interface for creating and managing HD wallets
    from seeds or mnemonics.
    """
    
    def __init__(self, seed: bytes, network: str = 'mainnet'):
        """
        Initialize HD wallet from seed.
        
        Args:
            seed: 64-byte seed (typically from BIP39 mnemonic).
            network: Network type ('mainnet' or 'testnet').
            
        Raises:
            BIP32Error: If seed is invalid.
        """
        if len(seed) not in [32, 64]:
            raise BIP32Error(f"Seed must be 32 or 64 bytes, got {len(seed)}")
        
        self.network = network
        self._master_node = self._generate_master_node(seed)
    
    def _generate_master_node(self, seed: bytes) -> HDNode:
        """
        Generate the master node from seed using BIP32.
        
        Args:
            seed: The seed bytes.
            
        Returns:
            The master HDNode.
        """
        # HMAC-SHA512 with "Bitcoin seed" key
        hmac_result = hmac_sha512(BIP32_HMAC_KEY, seed)
        
        # Split result
        master_private_key = hmac_result[:32]
        master_chain_code = hmac_result[32:]
        
        # Validate master private key
        private_int = int.from_bytes(master_private_key, byteorder='big')
        if private_int == 0 or private_int >= SECP256K1_N:
            raise BIP32Error("Invalid master private key generated")
        
        return HDNode(
            private_key=master_private_key,
            chain_code=master_chain_code,
            depth=0,
            parent_fingerprint=b'\x00\x00\x00\x00',
            child_number=0,
            network=self.network
        )
    
    @property 
    def master_node(self) -> HDNode:
        """Get the master node."""
        return self._master_node
    
    def derive_account(self, coin_type: int, account: int = 0) -> HDNode:
        """
        Derive account node using BIP44 standard path: m/44'/coin_type'/account'
        
        Args:
            coin_type: BIP44 coin type (e.g., 0 for Bitcoin, 60 for Ethereum).
            account: Account number (default 0).
            
        Returns:
            Account HDNode at m/44'/coin_type'/account'.
        """
        path = f"m/44'/{coin_type}'/{account}'"
        return self._master_node.derive_path(path)
    
    def derive_address_key(self, coin_type: int, account: int = 0, 
                          change: int = 0, address_index: int = 0) -> HDNode:
        """
        Derive address key using BIP44 standard path: m/44'/coin_type'/account'/change/address_index
        
        Args:
            coin_type: BIP44 coin type.
            account: Account number (default 0).
            change: Change flag (0 for external, 1 for internal/change, default 0).
            address_index: Address index (default 0).
            
        Returns:
            Address HDNode at the full BIP44 path.
        """
        path = f"m/44'/{coin_type}'/{account}'/{change}/{address_index}"
        return self._master_node.derive_path(path)
    
    def get_master_private_key(self) -> str:
        """Get the master extended private key (xprv)."""
        return self._master_node.serialize_private()
    
    def get_master_public_key(self) -> str:
        """Get the master extended public key (xpub)."""
        return self._master_node.serialize_public()
    
    @classmethod
    def from_mnemonic(cls, mnemonic: str, passphrase: str = "", network: str = 'mainnet') -> 'HDWallet':
        """
        Create HD wallet from BIP39 mnemonic phrase.
        
        Args:
            mnemonic: BIP39 mnemonic phrase.
            passphrase: Optional passphrase.
            network: Network type.
            
        Returns:
            New HDWallet instance.
        """
        from ..bip39 import mnemonic_to_seed
        seed = mnemonic_to_seed(mnemonic, passphrase)
        return cls(seed, network)
    
    @classmethod
    def from_extended_key(cls, extended_key: str) -> 'HDWallet':
        """
        Create HD wallet from extended key (xprv only).
        
        Args:
            extended_key: Extended private key (xprv).
            
        Returns:
            New HDWallet instance.
            
        Raises:
            BIP32Error: If extended key is not a private key.
        """
        master_node = HDNode.deserialize(extended_key)
        if not master_node.is_private:
            raise BIP32Error("Extended key must be a private key (xprv)")
        
        # Create new wallet instance
        wallet = cls.__new__(cls)
        wallet.network = master_node.network
        wallet._master_node = master_node
        return wallet


# Export main classes
__all__ = [
    'HDWallet',
    'HDNode', 
    'BIP32Error'
] 