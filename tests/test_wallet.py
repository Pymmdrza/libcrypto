"""Tests for the high-level Wallet wrapper."""
from __future__ import annotations

import pytest

from libcrypto.wallet import Wallet


def test_wallet_generates_known_bitcoin_address(deterministic_private_key_hex: str) -> None:
    """Wallet should reproduce the canonical P2PKH address for key = 1."""
    wallet = Wallet(deterministic_private_key_hex)
    address = wallet.get_address("bitcoin", "p2pkh")

    assert address == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"


def test_wallet_all_addresses_contains_configured_types(deterministic_private_key_hex: str) -> None:
    """get_all_addresses returns entries for each configured address type."""
    wallet = Wallet(deterministic_private_key_hex)
    addresses = wallet.get_all_addresses("bitcoin")

    assert set(addresses) == {"p2pkh", "p2sh-p2wpkh", "p2wpkh"}
    assert all(isinstance(value, str) for value in addresses.values())


def test_wallet_rejects_unknown_address_type(deterministic_private_key_hex: str) -> None:
    """Invalid address types trigger ValueError with descriptive message."""
    wallet = Wallet(deterministic_private_key_hex)

    with pytest.raises(ValueError):
        wallet.get_address("bitcoin", "p2wsh")


def test_wallet_rejects_unknown_coin(deterministic_private_key_hex: str) -> None:
    """Unsupported coins should raise ValueError early."""
    wallet = Wallet(deterministic_private_key_hex)

    with pytest.raises(ValueError):
        wallet.get_address("unknowncoin")
