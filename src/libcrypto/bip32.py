"""
BIP32 Hierarchical Deterministic (HD) Wallet Implementation

This module provides BIP32 compliant hierarchical deterministic wallet functionality
including master key generation from seed, child key derivation, and extended key
serialization (xprv/xpub format).
"""
import struct
from typing import Optional

from .constants import (
    BIP32_HARDENED_OFFSET, BIP32_HMAC_KEY, XPRV_MAINNET, XPUB_MAINNET,
    XPRV_TESTNET, XPUB_TESTNET, SECP256K1_N
)
from .formats import base58_check_encode, base58_check_decode, InvalidFormatError
from .hash import hmac_sha512, hash160
from .secp256k1 import private_key_to_public_key


class BIP32Error(ValueError):
    """Raised when BIP32 operations fail."""
    pass


class HDNode:
    """A single node in a BIP32 hierarchical deterministic wallet tree."""

    def __init__(self, private_key: Optional[bytes], chain_code: bytes,
                 depth: int = 0, parent_fingerprint: bytes = b'\x00\x00\x00\x00',
                 child_number: int = 0, network: str = 'mainnet'):

        if len(chain_code) != 32:
            raise BIP32Error(f"Chain code must be 32 bytes, got {len(chain_code)}")
        if private_key and len(private_key) != 32:
            raise BIP32Error(f"Private key must be 32 bytes, got {len(private_key)}")

        self._private_key = private_key
        self.chain_code = chain_code
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.child_number = child_number
        self.network = network

        self._public_key = None
        if self._private_key:
            self._derive_public_from_private()

    def _derive_public_from_private(self):
        private_int = int.from_bytes(self._private_key, 'big')
        self._public_key = private_key_to_public_key(private_int, compressed=True)

    @property
    def private_key(self) -> Optional[bytes]:
        return self._private_key

    @property
    def public_key(self) -> bytes:
        if self._public_key is None:
            # This case is for public-only derivation which is not implemented.
            raise BIP32Error("Public key not available or derivation from public key is not supported.")
        return self._public_key

    @property
    def is_private(self) -> bool:
        return self._private_key is not None

    @property
    def fingerprint(self) -> bytes:
        return hash160(self.public_key)[:4]

    def derive_child(self, index: int) -> 'HDNode':
        """Derive a child key at the given index."""
        is_hardened = index >= BIP32_HARDENED_OFFSET

        if is_hardened:
            if not self.is_private:
                raise BIP32Error("Cannot derive hardened child from a public key.")
            data = b'\x00' + self._private_key + struct.pack('>I', index)
        else:
            # Public key derivation is complex (point addition).
            # We will only support private key derivation for simplicity and security.
            if not self.is_private:
                raise BIP32Error("Derivation from public-only node is not supported.")
            data = self.public_key + struct.pack('>I', index)

        hmac_result = hmac_sha512(self.chain_code, data)
        child_key_material, child_chain_code = hmac_result[:32], hmac_result[32:]

        child_key_int = int.from_bytes(child_key_material, 'big')
        parent_key_int = int.from_bytes(self._private_key, 'big')

        derived_private_int = (child_key_int + parent_key_int) % SECP256K1_N
        if derived_private_int == 0:
            # In the rare case of an invalid key, BIP32 suggests trying the next index.
            # For simplicity, we raise an error.
            raise BIP32Error("Invalid child key generated, leads to key being zero.")

        child_private_key = derived_private_int.to_bytes(32, 'big')

        return HDNode(
            private_key=child_private_key,
            chain_code=child_chain_code,
            depth=self.depth + 1,
            parent_fingerprint=self.fingerprint,
            child_number=index,
            network=self.network
        )

    def derive_path(self, path: str) -> 'HDNode':
        """Derive a key using a derivation path string (e.g., "m/44'/0'/0'")."""
        if path == "m" or path == "/":
            return self
        if path.startswith(('m/', '/')):
            path = path[2:]

        node = self
        for segment in path.split('/'):
            if not segment: continue

            hardened = segment.endswith("'")
            index_str = segment[:-1] if hardened else segment

            try:
                index = int(index_str)
                if hardened:
                    index += BIP32_HARDENED_OFFSET
            except ValueError:
                raise BIP32Error(f"Invalid path segment: {segment}")

            node = node.derive_child(index)

        return node

    def serialize_private(self) -> str:
        """Serialize as an extended private key (xprv)."""
        if not self.is_private:
            raise BIP32Error("Cannot serialize a private key from a public-only node.")

        version = XPRV_MAINNET if self.network == 'mainnet' else XPRV_TESTNET

        data = struct.pack('>I', version)
        data += bytes([self.depth])
        data += self.parent_fingerprint
        data += struct.pack('>I', self.child_number)
        data += self.chain_code
        data += b'\x00' + self._private_key

        return base58_check_encode(data)

    def serialize_public(self) -> str:
        """Serialize as an extended public key (xpub)."""
        version = XPUB_MAINNET if self.network == 'mainnet' else XPUB_TESTNET

        data = struct.pack('>I', version)
        data += bytes([self.depth])
        data += self.parent_fingerprint
        data += struct.pack('>I', self.child_number)
        data += self.chain_code
        data += self.public_key

        return base58_check_encode(data)

    @classmethod
    def deserialize(cls, extended_key: str) -> 'HDNode':
        """Deserialize an extended key (xprv) to an HDNode."""
        try:
            data = base58_check_decode(extended_key)
        except InvalidFormatError as e:
            raise BIP32Error(f"Invalid extended key format: {e}") from e

        if len(data) != 78:
            raise BIP32Error(f"Extended key must be 78 bytes, got {len(data)}")

        version = struct.unpack('>I', data[:4])[0]

        if version not in [XPRV_MAINNET, XPRV_TESTNET]:
            raise BIP32Error("Deserialization of public extended keys (xpub) is not supported.")

        network = 'mainnet' if version == XPRV_MAINNET else 'testnet'

        depth = data[4]
        parent_fingerprint = data[5:9]
        child_number = struct.unpack('>I', data[9:13])[0]
        chain_code = data[13:45]

        if data[45] != 0x00:
            raise BIP32Error("Private key must be prefixed with 0x00.")
        private_key = data[46:78]

        return cls(
            private_key=private_key,
            chain_code=chain_code,
            depth=depth,
            parent_fingerprint=parent_fingerprint,
            child_number=child_number,
            network=network
        )


class HDWallet:
    """BIP32 Hierarchical Deterministic Wallet."""

    def __init__(self, seed: bytes, network: str = 'mainnet'):
        self.network = network
        self._master_node = self._generate_master_node(seed)

    def _generate_master_node(self, seed: bytes) -> HDNode:
        hmac_result = hmac_sha512(BIP32_HMAC_KEY, seed)
        master_private_key, master_chain_code = hmac_result[:32], hmac_result[32:]

        private_int = int.from_bytes(master_private_key, 'big')
        if not (1 <= private_int < SECP256K1_N):
            raise BIP32Error("Invalid master key generated from seed (out of curve order).")

        return HDNode(
            private_key=master_private_key,
            chain_code=master_chain_code,
            network=self.network
        )

    @property
    def master_node(self) -> HDNode:
        return self._master_node

    def derive_from_path(self, path: str) -> HDNode:
        """Derive a node from a full BIP32 path."""
        return self._master_node.derive_path(path)

    @classmethod
    def from_mnemonic(cls, mnemonic: str, passphrase: str = "", network: str = 'mainnet') -> 'HDWallet':
        """Create HDWallet from a BIP39 mnemonic."""
        from .mnemonic import mnemonic_to_seed
        seed = mnemonic_to_seed(mnemonic, passphrase)
        return cls(seed, network)
