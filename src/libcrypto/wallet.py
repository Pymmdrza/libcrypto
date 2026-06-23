"""High-level wallet interface."""
from __future__ import annotations

from typing import Dict, Union

from .addresses import AddressError, AddressGenerator
from .constants import BIP44_COIN_TYPES
from .keys import PrivateKey

# Public configuration kept as a simple dictionary for backward compatibility.
# New networks are additive; existing names and address-type names remain valid.
COIN_CONFIG = {
    "ethereum": {"uncompressed_required": True, "address_types": ["default"]},
    "ethereum_classic": {"uncompressed_required": True, "address_types": ["default"]},
    "bsc": {"uncompressed_required": True, "address_types": ["default"]},
    "binance_smart_chain": {"uncompressed_required": True, "address_types": ["default"]},
    "polygon": {"uncompressed_required": True, "address_types": ["default"]},
    "avalanche": {"uncompressed_required": True, "address_types": ["default"]},
    "arbitrum": {"uncompressed_required": True, "address_types": ["default"]},
    "optimism": {"uncompressed_required": True, "address_types": ["default"]},
    "base": {"uncompressed_required": True, "address_types": ["default"]},
    "tron": {"uncompressed_required": True, "address_types": ["default", "hex"]},
    "ripple": {"uncompressed_required": False, "address_types": ["default"]},
    "bitcoin": {
        "uncompressed_required": False,
        "address_types": ["p2pkh", "p2sh-p2wpkh", "p2wpkh", "p2tr"],
    },
    "litecoin": {
        "uncompressed_required": False,
        "address_types": ["p2pkh", "p2sh-p2wpkh", "p2wpkh"],
    },
    "dogecoin": {"uncompressed_required": False, "address_types": ["p2pkh"]},
    "dash": {"uncompressed_required": False, "address_types": ["p2pkh"]},
    "bitcoin_cash": {
        "uncompressed_required": False,
        "address_types": ["p2pkh", "cashaddr"],
    },
    "digibyte": {
        "uncompressed_required": False,
        "address_types": ["p2pkh", "p2sh-p2wpkh", "p2wpkh"],
    },
    "namecoin": {"uncompressed_required": False, "address_types": ["p2pkh"]},
    "testnet": {
        "uncompressed_required": False,
        "address_types": ["p2pkh", "p2sh-p2wpkh", "p2wpkh", "p2tr"],
    },
}


class Wallet:
    """Manage a single secp256k1 private key and generate addresses."""

    def __init__(self, private_key: Union[str, bytes, int, PrivateKey]):
        if isinstance(private_key, PrivateKey):
            self.private_key = private_key
        else:
            self.private_key = PrivateKey(private_key)

        self._public_key_compressed = self.private_key.get_public_key(compressed=True)
        self._public_key_uncompressed = self.private_key.get_public_key(compressed=False)

    def get_address(self, coin: str, address_type: str = "p2pkh") -> str:
        """Generate a single address for a coin and address type."""
        coin = coin.lower()
        address_type = address_type.lower()

        if coin not in COIN_CONFIG:
            if coin in BIP44_COIN_TYPES:
                raise ValueError(
                    f"Coin '{coin}' is recognized but not configured for simple address generation."
                )
            raise ValueError(f"Unsupported coin: '{coin}'")

        config = COIN_CONFIG[coin]
        public_key = (
            self._public_key_uncompressed
            if config["uncompressed_required"]
            else self._public_key_compressed
        )

        if address_type == "default":
            addr_type = "default"
        elif address_type == "p2pkh" and "default" in config["address_types"] and "p2pkh" not in config["address_types"]:
            # Preserve the historical behavior where account-based coins ignored
            # the default Wallet.get_address(..., address_type="p2pkh") argument.
            addr_type = "default"
        elif len(config["address_types"]) == 1 and config["address_types"][0] == "default":
            addr_type = "default"
        else:
            aliases = {
                "bech32": "p2wpkh",
                "segwit": "p2wpkh",
                "taproot": "p2tr",
                "taproot-bip86": "p2tr",
                "taproot_bip86": "p2tr",
                "hash": "hex",
                "hash_address": "hex",
            }
            normalized_type = aliases.get(address_type, address_type)
            if normalized_type not in config["address_types"]:
                raise ValueError(
                    f"Unsupported address type '{address_type}' for {coin}. "
                    f"Available types: {config['address_types']}"
                )
            addr_type = normalized_type

        try:
            return AddressGenerator.from_public_key(public_key.bytes, addr_type, coin)
        except AddressError as exc:
            raise ValueError(f"Could not generate address for {coin}: {exc}") from exc

    def get_all_addresses(self, coin: str) -> Dict[str, str]:
        """Generate all configured address formats for a coin."""
        coin = coin.lower()
        if coin not in COIN_CONFIG:
            raise ValueError(f"Unsupported coin: '{coin}'")

        addresses: Dict[str, str] = {}
        for addr_type in COIN_CONFIG[coin]["address_types"]:
            try:
                addresses[addr_type] = self.get_address(coin, addr_type)
            except (ValueError, NotImplementedError, AddressError) as exc:
                addresses[addr_type] = f"Error: {exc}"
        return addresses

    @classmethod
    def generate(cls) -> "Wallet":
        """Create a wallet with a newly generated private key."""
        return cls(PrivateKey.generate())

    def __repr__(self) -> str:
        return "Wallet(private_key='<hidden>')"
