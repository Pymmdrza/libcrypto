"""Cryptocurrency address generation helpers.

This module keeps the existing ``AddressGenerator`` API while providing fully
internal implementations for Bitcoin-style, Ethereum/EVM, TRON, Ripple, SegWit,
Taproot, and Bitcoin Cash CashAddr address formats.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from .constants import (
    ADDRESS_VERSIONS,
    BASE58_ALPHABET,
    BECH32_HRP,
    CASHADDR_HRP,
    SECP256K1_N,
    SECP256K1_P,
)
from .formats import base58_check_encode
from .hash import hash160, keccak256, sha256
from .secp256k1 import private_key_to_public_key, public_key_to_point_coords


class AddressError(ValueError):
    """Raised when address generation fails."""


EVM_COMPATIBLE_NETWORKS = {
    "ethereum",
    "ethereum_classic",
    "bsc",
    "binance_smart_chain",
    "polygon",
    "avalanche",
    "arbitrum",
    "optimism",
    "base",
}


class Bech32:
    """Bech32 and Bech32m encoding for SegWit-style addresses."""

    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    BECH32_CONST = 1
    BECH32M_CONST = 0x2BC830A3

    @classmethod
    def _polymod(cls, values: List[int]) -> int:
        generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
        chk = 1
        for value in values:
            top = chk >> 25
            chk = ((chk & 0x1FFFFFF) << 5) ^ value
            for i in range(5):
                if (top >> i) & 1:
                    chk ^= generator[i]
        return chk

    @classmethod
    def _hrp_expand(cls, hrp: str) -> List[int]:
        return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]

    @classmethod
    def _create_checksum(cls, hrp: str, data: List[int], spec: str = "bech32") -> List[int]:
        if spec == "bech32":
            const = cls.BECH32_CONST
        elif spec == "bech32m":
            const = cls.BECH32M_CONST
        else:
            raise AddressError("Bech32 spec must be 'bech32' or 'bech32m'.")
        values = cls._hrp_expand(hrp) + data
        polymod = cls._polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
        return [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]

    @classmethod
    def encode(cls, hrp: str, data: List[int], spec: str = "bech32") -> str:
        hrp = hrp.lower()
        combined = data + cls._create_checksum(hrp, data, spec)
        return hrp + "1" + "".join(cls.CHARSET[d] for d in combined)

    @classmethod
    def convert_bits(
        cls, data, frombits: int, tobits: int, pad: bool = True
    ) -> Optional[List[int]]:
        acc = 0
        bits = 0
        ret: List[int] = []
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

    @classmethod
    def encode_witness(cls, hrp: str, witness_version: int, witness_program: bytes) -> str:
        if not 0 <= witness_version <= 16:
            raise AddressError("Witness version must be in range 0..16.")
        if witness_version == 0 and len(witness_program) not in (20, 32):
            raise AddressError("Witness version 0 program must be 20 or 32 bytes.")
        if witness_version > 0 and not 2 <= len(witness_program) <= 40:
            raise AddressError("Witness version 1..16 program must be 2..40 bytes.")

        converted = cls.convert_bits(witness_program, 8, 5, True)
        if converted is None:
            raise AddressError("Failed to convert witness program for Bech32 encoding.")
        spec = "bech32" if witness_version == 0 else "bech32m"
        return cls.encode(hrp, [witness_version] + converted, spec)


class CashAddr:
    """Bitcoin Cash CashAddr encoder for 20-byte P2PKH/P2SH hashes."""

    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    @classmethod
    def _prefix_expand(cls, prefix: str) -> List[int]:
        return [ord(char) & 0x1F for char in prefix] + [0]

    @classmethod
    def _polymod(cls, values: List[int]) -> int:
        generator = [
            0x98F2BC8E61,
            0x79B76D99E2,
            0xF33E5FB3C4,
            0xAE2EABE2A8,
            0x1E4F43E470,
        ]
        chk = 1
        for value in values:
            top = chk >> 35
            chk = ((chk & 0x07FFFFFFFF) << 5) ^ value
            for i in range(5):
                if (top >> i) & 1:
                    chk ^= generator[i]
        return chk ^ 1

    @classmethod
    def _create_checksum(cls, prefix: str, payload: List[int]) -> List[int]:
        polymod = cls._polymod(cls._prefix_expand(prefix) + payload + [0] * 8)
        return [(polymod >> 5 * (7 - i)) & 31 for i in range(8)]

    @classmethod
    def encode(cls, prefix: str, payload: bytes, kind: str = "p2pkh") -> str:
        if len(payload) != 20:
            raise AddressError("CashAddr currently supports 20-byte payloads only.")
        if kind not in {"p2pkh", "p2sh"}:
            raise AddressError("CashAddr kind must be 'p2pkh' or 'p2sh'.")

        type_bits = 0 if kind == "p2pkh" else 1
        size_bits = 0  # 160-bit hash.
        version = (type_bits << 3) | size_bits
        converted = Bech32.convert_bits(bytes([version]) + payload, 8, 5, True)
        if converted is None:
            raise AddressError("Failed to convert CashAddr payload.")
        prefix = prefix.lower()
        checksum = cls._create_checksum(prefix, converted)
        return prefix + ":" + "".join(cls.CHARSET[d] for d in converted + checksum)


def _tagged_hash(tag: str, message: bytes) -> bytes:
    tag_hash = sha256(tag.encode("ascii"))
    return sha256(tag_hash + tag_hash + message)


def _affine_add(
    p1: Optional[Tuple[int, int]], p2: Optional[Tuple[int, int]]
) -> Optional[Tuple[int, int]]:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % SECP256K1_P == 0:
        return None
    if x1 == x2:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, SECP256K1_P) % SECP256K1_P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, SECP256K1_P) % SECP256K1_P
    x3 = (slope * slope - x1 - x2) % SECP256K1_P
    y3 = (slope * (x1 - x3) - y1) % SECP256K1_P
    return x3, y3


def _base58check_to_hex_address(address_bytes: bytes) -> str:
    return address_bytes.hex().upper()


class AddressGenerator:
    """Address generator for multiple cryptocurrencies."""

    @classmethod
    def from_public_key(cls, public_key: bytes, address_type: str, network: str) -> str:
        """Generate an address from a secp256k1 public key."""
        network = network.lower()
        address_type = address_type.lower()

        if network in EVM_COMPATIBLE_NETWORKS:
            return cls._generate_ethereum_address(public_key)
        if network == "tron":
            if address_type in {"hex", "hash", "hash_address"}:
                return cls._generate_tron_hash_address(public_key)
            return cls._generate_tron_address(public_key)
        if network == "ripple":
            return cls._generate_ripple_address(public_key)
        if network in ("solana", "ton", "cardano"):
            raise NotImplementedError(
                f"{network.capitalize()} does not use secp256k1 address derivation in this API."
            )
        return cls._generate_bitcoin_style_address(public_key, address_type, network)

    @classmethod
    def _generate_bitcoin_style_address(cls, public_key: bytes, address_type: str, network: str) -> str:
        if network not in ADDRESS_VERSIONS:
            raise AddressError(f"Unsupported network: {network}")

        versions = ADDRESS_VERSIONS[network]
        key_hash = hash160(public_key)

        if address_type in {"p2pkh", "legacy"}:
            return base58_check_encode(bytes([versions["p2pkh"]]) + key_hash)

        if address_type in {"p2sh-p2wpkh", "p2sh_p2wpkh", "nested-segwit", "nested_segwit"}:
            redeem_script = b"\x00\x14" + key_hash
            script_hash = hash160(redeem_script)
            return base58_check_encode(bytes([versions["p2sh"]]) + script_hash)

        if address_type in {"p2wpkh", "bech32", "segwit"}:
            if network not in BECH32_HRP:
                raise AddressError(f"Native SegWit is not supported for network: {network}")
            return Bech32.encode_witness(BECH32_HRP[network], 0, key_hash)

        if address_type in {"p2tr", "taproot", "taproot-bip86", "taproot_bip86"}:
            if network not in BECH32_HRP:
                raise AddressError(f"Taproot is not supported for network: {network}")
            return cls._generate_taproot_bip86_address(public_key, BECH32_HRP[network])

        if network == "bitcoin_cash" and address_type in {"cashaddr", "p2pkh-cashaddr"}:
            return CashAddr.encode(CASHADDR_HRP[network], key_hash, "p2pkh")

        raise AddressError(f"Unsupported address type for {network}: {address_type}")

    @classmethod
    def _get_uncompressed_pubkey(cls, public_key: bytes) -> bytes:
        """Return uncompressed public key as 64 bytes without the 0x04 prefix."""
        if len(public_key) == 33:
            x, y = public_key_to_point_coords(public_key)
            return x.to_bytes(32, "big") + y.to_bytes(32, "big")
        if len(public_key) == 65 and public_key[0] == 0x04:
            return public_key[1:]
        if len(public_key) == 64:
            return public_key
        raise AddressError(f"Invalid public key length for this operation: {len(public_key)}")

    @classmethod
    def _generate_ethereum_address(cls, public_key: bytes) -> str:
        """Generate an EIP-55 checksummed Ethereum/EVM address."""
        uncompressed_key = cls._get_uncompressed_pubkey(public_key)
        address_hex = keccak256(uncompressed_key)[-20:].hex()
        checksum_hash = keccak256(address_hex.encode("ascii")).hex()
        checksummed = "".join(
            char.upper() if int(checksum_hash[index], 16) >= 8 else char
            for index, char in enumerate(address_hex)
        )
        return "0x" + checksummed

    @classmethod
    def _generate_tron_hash_address(cls, public_key: bytes) -> str:
        """Generate TRON 0x41-prefixed hex address without Base58Check encoding."""
        uncompressed_key = cls._get_uncompressed_pubkey(public_key)
        address_bytes = b"\x41" + keccak256(uncompressed_key)[-20:]
        return _base58check_to_hex_address(address_bytes)

    @classmethod
    def _generate_tron_address(cls, public_key: bytes) -> str:
        """Generate TRON Base58Check address."""
        uncompressed_key = cls._get_uncompressed_pubkey(public_key)
        address_bytes = b"\x41" + keccak256(uncompressed_key)[-20:]
        return base58_check_encode(address_bytes)

    @classmethod
    def _generate_taproot_bip86_address(cls, public_key: bytes, hrp: str) -> str:
        """Generate a single-key BIP86-style Taproot P2TR address."""
        x, y = public_key_to_point_coords(public_key)
        internal_point = (x, y if y % 2 == 0 else SECP256K1_P - y)
        internal_key = internal_point[0].to_bytes(32, "big")
        tweak = int.from_bytes(_tagged_hash("TapTweak", internal_key), "big")
        if tweak >= SECP256K1_N:
            raise AddressError("Invalid Taproot tweak.")

        if tweak == 0:
            output_point = internal_point
        else:
            tweak_public_key = private_key_to_public_key(tweak, compressed=False)
            tweak_point = public_key_to_point_coords(tweak_public_key)
            output_point = _affine_add(internal_point, tweak_point)

        if output_point is None:
            raise AddressError("Invalid Taproot output key.")

        return Bech32.encode_witness(hrp, 1, output_point[0].to_bytes(32, "big"))

    @classmethod
    def _generate_ripple_address(cls, public_key: bytes) -> str:
        """Generate a Ripple/XRP classic account address."""
        if len(public_key) == 65:
            from .secp256k1 import compress_public_key

            public_key = compress_public_key(public_key)
        if len(public_key) != 33:
            raise AddressError(f"Invalid public key length for Ripple: {len(public_key)}")

        key_hash = hash160(public_key)
        versioned_payload = b"\x00" + key_hash
        ripple_alphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
        return base58_check_encode(versioned_payload, alphabet=ripple_alphabet)


__all__ = [
    "AddressGenerator",
    "AddressError",
    "Bech32",
    "CashAddr",
]
