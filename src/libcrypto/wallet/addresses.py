"""
Cryptocurrency Address Generation

This module provides address generation functionality for multiple cryptocurrencies
including Bitcoin, Ethereum, Litecoin, and others. Supports various address formats
like P2PKH, P2SH, P2WPKH, SegWit, and Ethereum-style addresses.
"""

from typing import Union, Optional

from ..Hash.SHA256 import SHA256Hash
from ..Hash.RIPEMD160 import RIPEMD160Hash
from ..Util.constants import ADDRESS_VERSIONS, BECH32_HRP
from ..wallet.formats import base58_check_encode, base58_check_decode, InvalidFormatError
from ..wallet.crypto_utils import keccak256
from ..wallet.formats import base58_encode
from ..wallet.secp256k1 import public_key_to_point

class AddressError(ValueError):
    """Raised when address generation fails."""
    pass


class Bech32:
    """Bech32 encoding/decoding for SegWit addresses."""
    
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    BECH32_CONST = 1
    BECH32M_CONST = 0x2bc830a3
    
    @classmethod
    def _polymod(cls, values):
        """Calculate Bech32 polymod."""
        GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for value in values:
            top = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ value
            for i in range(5):
                chk ^= GEN[i] if ((top >> i) & 1) else 0
        return chk
    
    @classmethod
    def _hrp_expand(cls, hrp):
        """Expand HRP for checksum calculation."""
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    
    @classmethod
    def _verify_checksum(cls, hrp, data, spec):
        """Verify Bech32 checksum."""
        const = cls.BECH32_CONST if spec == "bech32" else cls.BECH32M_CONST
        return cls._polymod(cls._hrp_expand(hrp) + data) == const
    
    @classmethod
    def _create_checksum(cls, hrp, data, spec):
        """Create Bech32 checksum."""
        const = cls.BECH32_CONST if spec == "bech32" else cls.BECH32M_CONST
        values = cls._hrp_expand(hrp) + data
        polymod = cls._polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
        return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    
    @classmethod
    def encode(cls, hrp, data, spec="bech32"):
        """Encode data with Bech32."""
        combined = data + cls._create_checksum(hrp, data, spec)
        return hrp + '1' + ''.join([cls.CHARSET[d] for d in combined])
    
    @classmethod
    def decode(cls, bech_string):
        """Decode Bech32 string."""
        if ((any(ord(x) < 33 or ord(x) > 126 for x in bech_string)) or
            (bech_string.lower() != bech_string and bech_string.upper() != bech_string)):
            return (None, None, None)
        
        bech_string = bech_string.lower()
        pos = bech_string.rfind('1')
        if pos < 1 or pos + 7 > len(bech_string) or pos + 1 + 6 > len(bech_string):
            return (None, None, None)
        
        hrp = bech_string[:pos]
        data = [cls.CHARSET.find(x) for x in bech_string[pos+1:]]
        if not all(x >= 0 for x in data):
            return (None, None, None)
        
        spec = "bech32" if cls._verify_checksum(hrp, data, "bech32") else "bech32m" if cls._verify_checksum(hrp, data, "bech32m") else None
        if spec is None:
            return (None, None, None)
        
        return (hrp, data[:-6], spec)
    
    @classmethod
    def convert_bits(cls, data, frombits, tobits, pad=True):
        """Convert between bit groups."""
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        max_acc = (1 << (frombits + tobits - 1)) - 1
        for value in data:
            if value < 0 or (value >> frombits):
                return None
            acc = ((acc << frombits) | value) & max_acc
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        if pad:
            if bits:
                ret.append((acc << (tobits - bits)) & maxv)
        elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
            return None
        return ret


class AddressGenerator:
    """
    Address generator for multiple cryptocurrencies.
    
    Supports generation of addresses from public keys for various
    cryptocurrencies and address formats.
    """
    
    @staticmethod
    def _hash160(data: bytes) -> bytes:
        """Compute RIPEMD160(SHA256(data))."""
        sha256_hash = SHA256Hash(data).digest()
        return RIPEMD160Hash(sha256_hash).digest()
    
    @staticmethod
    def _double_sha256(data: bytes) -> bytes:
        """Compute double SHA256."""
        first_hash = SHA256Hash(data).digest()
        return SHA256Hash(first_hash).digest()
    
    @classmethod
    def from_public_key(cls, public_key: bytes, address_type: str, network: str) -> str:
        """
        Generate address from public key.
        
        Args:
            public_key: Public key bytes (compressed or uncompressed).
            address_type: Address type ('p2pkh', 'p2sh', 'p2wpkh', 'p2wsh', 'ethereum').
            network: Network/currency name.
            
        Returns:
            The generated address string.
            
        Raises:
            AddressError: If address generation fails.
        """
        if network == 'ethereum':
            return cls._generate_ethereum_address(public_key)
        elif network == 'tron':
            return cls._generate_tron_address(public_key)
        elif network == 'solana':
            return cls._generate_solana_address(public_key)
        elif network == 'ripple':
            return cls._generate_ripple_address(public_key)
        elif network == 'ton':
            return cls._generate_ton_address(public_key)
        else:
            # Bitcoin-like currencies
            return cls._generate_bitcoin_like_address(public_key, address_type, network)
    
    @classmethod
    def _generate_bitcoin_like_address(cls, public_key: bytes, address_type: str, network: str) -> str:
        """Generate Bitcoin-like address."""
        if network not in ADDRESS_VERSIONS:
            raise AddressError(f"Unsupported network: {network}")
        
        versions = ADDRESS_VERSIONS[network]
        
        if address_type == 'p2pkh':
            # Pay to Public Key Hash
            hash160 = cls._hash160(public_key)
            versioned_payload = bytes([versions['p2pkh']]) + hash160
            return base58_check_encode(versioned_payload)
        
        elif address_type == 'p2sh':
            # Pay to Script Hash (P2SH)
            # For simplicity, we'll create a basic P2SH address
            # In practice, this would require a specific script
            hash160 = cls._hash160(public_key)
            versioned_payload = bytes([versions['p2sh']]) + hash160
            return base58_check_encode(versioned_payload)
        
        elif address_type == 'p2wpkh':
            # Pay to Witness Public Key Hash (SegWit v0)
            if network not in BECH32_HRP:
                raise AddressError(f"SegWit not supported for network: {network}")
            
            hash160 = cls._hash160(public_key)
            # Witness version 0, 20-byte program
            converted = Bech32.convert_bits(hash160, 8, 5)
            if converted is None:
                raise AddressError("Failed to convert bits for Bech32")
            
            data = [0] + converted  # Version 0
            return Bech32.encode(BECH32_HRP[network], data)
        
        elif address_type == 'p2wsh':
            # Pay to Witness Script Hash (SegWit v0)
            if network not in BECH32_HRP:
                raise AddressError(f"SegWit not supported for network: {network}")
            
            # For demonstration, we'll hash the public key (in practice, this would be a script hash)
            script_hash = SHA256Hash(public_key).digest()
            converted = Bech32.convert_bits(script_hash, 8, 5)
            if converted is None:
                raise AddressError("Failed to convert bits for Bech32")
            
            data = [0] + converted  # Version 0
            return Bech32.encode(BECH32_HRP[network], data)
        
        elif address_type in ['compressed', 'uncompressed']:
            # Legacy format specification
            return cls._generate_bitcoin_like_address(public_key, 'p2pkh', network)
        
        else:
            raise AddressError(f"Unsupported address type: {address_type}")
    
    @classmethod
    def _generate_ethereum_address(cls, public_key: bytes) -> str:
        """Generate Ethereum address from public key."""
        # Ethereum uses the last 20 bytes of Keccac256(public_key)
        # Handle both compressed and uncompressed public keys
        if len(public_key) == 65 and public_key[0] == 0x04:
            # Uncompressed key with 0x04 prefix - remove prefix
            public_key = public_key[1:]
        elif len(public_key) == 33:
            # Compressed key - convert to uncompressed
            
            try:
                # Convert compressed public key to uncompressed
                point = public_key_to_point(public_key)
                # Extract x and y coordinates (32 bytes each)
                x_bytes = point.x.to_bytes(32, byteorder='big')
                y_bytes = point.y.to_bytes(32, byteorder='big')
                public_key = x_bytes + y_bytes
            except Exception as e:
                raise AddressError(f"Failed to convert compressed public key: {e}")
        elif len(public_key) == 64:
            # Already uncompressed without prefix
            pass
        else:
            raise AddressError(f"Invalid public key length for Ethereum: {len(public_key)}")
        
        if len(public_key) != 64:
            raise AddressError(f"Invalid public key length for Ethereum after processing: {len(public_key)}")
        
        # Compute Keccac256 hash
        keccac_hash = keccac256(public_key)
        
        # Take last 20 bytes as address
        address_bytes = keccac_hash[-20:]
        address_hex = address_bytes.hex()
        
        # Apply EIP-55 checksum (mixed case)
        address_hash = keccac256(address_hex.encode())
        checksummed = ""
        
        for i, char in enumerate(address_hex):
            if char.isdigit():
                checksummed += char
            else:
                # Use uppercase if the corresponding hex digit is >= 8
                checksummed += char.upper() if (address_hash[i // 2] >> (4 * (1 - i % 2))) & 0xf >= 8 else char.lower()
        
        return "0x" + checksummed
    
    @classmethod
    def _generate_tron_address(cls, public_key: bytes) -> str:
        """Generate Tron address from public key."""
        # Tron addresses are similar to Ethereum but with different prefix
        # Remove 0x04 prefix if present
        if len(public_key) == 65 and public_key[0] == 0x04:
            public_key = public_key[1:]
        elif len(public_key) == 33:
            # Compressed key - convert to uncompressed
            
            try:
                # Convert compressed public key to uncompressed
                point = public_key_to_point(public_key)
                # Extract x and y coordinates (32 bytes each)
                x_bytes = point.x.to_bytes(32, byteorder='big')
                y_bytes = point.y.to_bytes(32, byteorder='big')
                public_key = x_bytes + y_bytes
            except Exception as e:
                raise AddressError(f"Failed to convert compressed public key: {e}")
        elif len(public_key) == 64:
            # Already uncompressed without prefix
            pass
        else:
            raise AddressError(f"Invalid public key length for Tron: {len(public_key)}")
        
        if len(public_key) != 64:
            raise AddressError(f"Invalid public key length for Tron: {len(public_key)}")
        
        # Compute Keccak256 hash
        keccak_hash = keccak256(public_key)
        
        # Take last 20 bytes and add Tron prefix (0x41)
        address_bytes = b'\x41' + keccak_hash[-20:]
        
        # Encode with Base58Check
        return base58_check_encode(address_bytes)
    
    @classmethod 
    def _generate_solana_address(cls, public_key: bytes) -> str:
        """Generate Solana address from public key."""
        # Solana uses Ed25519 public keys directly as addresses
        # For now, we'll use a simplified approach
        if len(public_key) != 32:
            # If this is a secp256k1 key, we need to convert it
            # For simplicity, we'll hash it to get 32 bytes
            address_bytes = SHA256Hash(public_key).digest()
        else:
            address_bytes = public_key
        
        # Solana addresses are Base58 encoded (no checksum)
        from libcrypto.wallet.formats import base58_encode
        return base58_encode(address_bytes)
    
    @classmethod
    def _generate_ripple_address(cls, public_key: bytes) -> str:
        """Generate Ripple (XRP) address from public key."""
        # Ripple uses RIPEMD160(SHA256(public_key)) with special encoding
        hash160 = cls._hash160(public_key)
        
        # Add Ripple address type prefix (0x00)
        versioned_payload = b'\x00' + hash160
        
        # Use Base58Check but with Ripple's custom alphabet
        ripple_alphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
        return base58_check_encode(versioned_payload)  # Using standard for now
    
    @classmethod
    def _generate_ton_address(cls, public_key: bytes) -> str:
        """Generate TON address from public key."""
        # TON uses a complex address format
        # For simplicity, we'll use a basic approach
        address_bytes = cls._hash160(public_key)
        
        # TON addresses are typically Base64url encoded
        # For now, we'll use Base58 for consistency
        
        return base58_encode(address_bytes)
    
    @classmethod
    def generate_multiple_formats(cls, public_key: bytes, network: str) -> dict:
        """
        Generate multiple address formats for a given network.
        
        Args:
            public_key: Public key bytes.
            network: Network name.
            
        Returns:
            Dictionary of {format: address} pairs.
        """
        addresses = {}
        
        try:
            if network == 'bitcoin':
                addresses.update({
                    'p2pkh': cls.from_public_key(public_key, 'p2pkh', network),
                    'p2sh': cls.from_public_key(public_key, 'p2sh', network),
                    'p2wpkh': cls.from_public_key(public_key, 'p2wpkh', network),
                    'p2wsh': cls.from_public_key(public_key, 'p2wsh', network),
                })
            elif network in ['litecoin', 'dogecoin', 'dash', 'bitcoin_cash', 'bitcoin_gold', 'digibyte']:
                addresses.update({
                    'p2pkh': cls.from_public_key(public_key, 'p2pkh', network),
                    'p2sh': cls.from_public_key(public_key, 'p2sh', network),
                })
            elif network == 'ethereum':
                addresses['ethereum'] = cls.from_public_key(public_key, 'ethereum', network)
            elif network == 'tron':
                addresses['tron'] = cls.from_public_key(public_key, 'tron', network)
            elif network == 'solana':
                addresses['solana'] = cls.from_public_key(public_key, 'solana', network)
            elif network == 'ripple':
                addresses['ripple'] = cls.from_public_key(public_key, 'ripple', network)
            elif network == 'ton':
                addresses['ton'] = cls.from_public_key(public_key, 'ton', network)
            else:
                # Generic Bitcoin-like
                addresses['p2pkh'] = cls.from_public_key(public_key, 'p2pkh', network)
        except Exception as e:
            # Log error but continue with other formats
            addresses[f'error_{network}'] = str(e)
        
        return addresses
    
    @classmethod
    def validate_address(cls, address: str, network: str) -> bool:
        """
        Validate an address for a given network.
        
        Args:
            address: The address to validate.
            network: The network name.
            
        Returns:
            True if address is valid.
        """
        try:
            if network == 'ethereum':
                # Basic Ethereum address validation
                if not address.startswith('0x') or len(address) != 42:
                    return False
                # Check if hex
                int(address[2:], 16)
                return True
            
            elif network in ADDRESS_VERSIONS:
                # Bitcoin-like address validation
                if address.startswith(('bc1', 'tb1')):
                    # Bech32 address
                    hrp, data, spec = Bech32.decode(address)
                    return hrp is not None and data is not None
                else:
                    # Base58Check address
                    try:
                        decoded = base58_check_decode(address)
                        return len(decoded) == 21  # 1 byte version + 20 byte hash
                    except InvalidFormatError:
                        return False
            
            return False
        except Exception:
            return False


# Export main classes
__all__ = [
    'AddressGenerator',
    'AddressError',
    'Bech32'
] 