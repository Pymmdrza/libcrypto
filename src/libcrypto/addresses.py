"""
Cryptocurrency Address Generation

This module provides address generation functionality for multiple cryptocurrencies
including Bitcoin, Ethereum, Litecoin, and others. Supports various address formats
like P2PKH, P2SH, P2WPKH, SegWit, and Ethereum-style addresses.
"""
from typing import Union

from .hash import sha256, hash160, keccak256
from .constants import ADDRESS_VERSIONS, BECH32_HRP
from .formats import base58_check_encode, base58_encode, InvalidFormatError
from .secp256k1 import public_key_to_point_coords, Secp256k1Error


class AddressError(ValueError):
    """Raised when address generation fails."""
    pass


class Bech32:
    """Bech32 encoding/decoding for SegWit addresses."""
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    BECH32_CONST = 1

    @classmethod
    def _polymod(cls, values):
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
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

    @classmethod
    def _create_checksum(cls, hrp, data):
        values = cls._hrp_expand(hrp) + data
        polymod = cls._polymod(values + [0, 0, 0, 0, 0, 0]) ^ cls.BECH32_CONST
        return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

    @classmethod
    def encode(cls, hrp, data):
        combined = data + cls._create_checksum(hrp, data)
        return hrp + '1' + ''.join([cls.CHARSET[d] for d in combined])

    @classmethod
    def convert_bits(cls, data, frombits, tobits, pad=True):
        acc, bits, ret, maxv = 0, 0, [], (1 << tobits) - 1
        for value in data:
            if value < 0 or (value >> frombits):
                return None
            acc = (acc << frombits) | value
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        if pad and bits:
            ret.append((acc << (tobits - bits)) & maxv)
        elif not pad and (bits >= frombits or ((acc << (tobits - bits)) & maxv)):
            return None
        return ret


class AddressGenerator:
    """
    Address generator for multiple cryptocurrencies.
    """

    @classmethod
    def from_public_key(cls, public_key: bytes, address_type: str, network: str) -> str:
        """
        Generate address from a public key.
        """
        if network == 'ethereum':
            return cls._generate_ethereum_address(public_key)
        elif network == 'tron':
            return cls._generate_tron_address(public_key)
        elif network == 'ripple':
            return cls._generate_ripple_address(public_key)
        elif network in ('solana', 'ton'):
            # These networks use Ed25519, which is a different curve.
            # Providing a secp256k1 key will result in an invalid address.
            raise NotImplementedError(
                f"{network.capitalize()} uses the Ed25519 curve. "
                "Address generation from secp256k1 keys is not supported and would be incorrect."
            )
        else:
            return cls._generate_bitcoin_style_address(public_key, address_type, network)

    @classmethod
    def _generate_bitcoin_style_address(cls, public_key: bytes, address_type: str, network: str) -> str:
        """Generate Bitcoin-like addresses (P2PKH, P2SH, SegWit)."""
        if network not in ADDRESS_VERSIONS:
            raise AddressError(f"Unsupported network: {network}")

        versions = ADDRESS_VERSIONS[network]
        key_hash = hash160(public_key)

        if address_type == 'p2pkh':
            versioned_payload = bytes([versions['p2pkh']]) + key_hash
            return base58_check_encode(versioned_payload)

        elif address_type == 'p2sh-p2wpkh':
            # P2SH-wrapped SegWit address (for compatibility)
            redeem_script = b'\x00\x14' + key_hash
            script_hash = hash160(redeem_script)
            versioned_payload = bytes([versions['p2sh']]) + script_hash
            return base58_check_encode(versioned_payload)

        elif address_type == 'p2wpkh':
            # Native SegWit (Bech32)
            if network not in BECH32_HRP:
                raise AddressError(f"SegWit (Bech32) not supported for network: {network}")

            converted = Bech32.convert_bits(key_hash, 8, 5)
            if converted is None:
                raise AddressError("Failed to convert bits for Bech32 encoding.")

            return Bech32.encode(BECH32_HRP[network], [0] + converted)

        else:
            raise AddressError(f"Unsupported address type for {network}: {address_type}")

    @classmethod
    def _get_uncompressed_pubkey(cls, public_key: bytes) -> bytes:
        """Ensures the public key is in uncompressed format (64 bytes, no prefix)."""
        if len(public_key) == 33:  # Compressed
            try:
                point = public_key_to_point_coords(public_key)
                return point.x.to_bytes(32, 'big') + point.y.to_bytes(32, 'big')
            except Exception as e:
                raise AddressError(f"Failed to decompress public key: {e}")
        elif len(public_key) == 65 and public_key[0] == 0x04:  # Uncompressed with prefix
            return public_key[1:]
        elif len(public_key) == 64:  # Uncompressed without prefix
            return public_key
        else:
            raise AddressError(f"Invalid public key length for this operation: {len(public_key)}")

    @classmethod
    def _generate_ethereum_address(cls, public_key: bytes) -> str:
        """Generate Ethereum address (with EIP-55 checksum)."""
    
        uncompressed_key = cls._get_uncompressed_pubkey(public_key)

        keccak_hash = keccak256(uncompressed_key)
        address_bytes = keccak_hash[-20:]
        address_hex = address_bytes.hex()

        # EIP-55 checksum
        checksum_hash = keccak256(address_hex.encode('ascii')).hex()
        checksummed = '0x'
        for i, char in enumerate(address_hex):
            if int(checksum_hash[i], 16) >= 8:
                checksummed += char.upper()
            else:
                checksummed += char
        return checksummed

    @classmethod
    def _generate_tron_address(cls, public_key: bytes) -> str:
        """Generate TRON address."""
        uncompressed_key = cls._get_uncompressed_pubkey(public_key)

        keccak_hash = keccak256(uncompressed_key)
        address_bytes = b'\x41' + keccak_hash[-20:]  # TRON prefix 0x41

        return base58_check_encode(address_bytes)

    @classmethod
    def _generate_ripple_address(cls, public_key: bytes) -> str:
        """Generate Ripple (XRP) address."""
        # Ripple requires a compressed public key
        if len(public_key) == 65:
            from .secp256k1 import compress_public_key
            public_key = compress_public_key(public_key)

        if len(public_key) != 33:
            raise AddressError(f"Invalid public key length for Ripple: {len(public_key)}")

        key_hash = hash160(public_key)
        versioned_payload = b'\x00' + key_hash  # Ripple account ID prefix

        # Ripple uses a specific Base58 alphabet
        ripple_alphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
        return base58_check_encode(versioned_payload, alphabet=ripple_alphabet)
