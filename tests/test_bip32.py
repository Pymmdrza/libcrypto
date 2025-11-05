"""BIP32 HD wallet regression tests."""
from __future__ import annotations

import pytest

from libcrypto.bip32 import BIP32Error, HDWallet


SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
MASTER_XPRV = (
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVv"
    "vNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
)
CHILD_XPRV = (
    "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53K"
    "w1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
)


def test_master_serialization_matches_reference() -> None:
    """Master node serialization should match the official BIP32 test vector."""
    wallet = HDWallet(SEED)
    assert wallet.master_node.serialize_private() == MASTER_XPRV


def test_child_derivation_matches_reference() -> None:
    """Deriving m/0'/1 should match the corresponding reference xprv."""
    wallet = HDWallet(SEED)
    child = wallet.derive_from_path("m/0'/1")

    assert child.serialize_private() == CHILD_XPRV


def test_derivation_rejects_invalid_segment() -> None:
    """Invalid derivation strings must raise BIP32Error."""
    wallet = HDWallet(SEED)

    with pytest.raises(BIP32Error):
        wallet.derive_from_path("m/44'/0'/abc")
