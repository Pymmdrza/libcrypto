"""Mnemonic helpers should follow BIP39 reference vectors."""
from __future__ import annotations

import pytest

from libcrypto.mnemonic import (
    InvalidMnemonicError,
    generate_mnemonic,
    mnemonic_to_entropy,
    mnemonic_to_seed,
    validate_mnemonic,
)


REFERENCE_MNEMONIC = "abandon " * 11 + "about"
REFERENCE_MNEMONIC = REFERENCE_MNEMONIC.strip()
REFERENCE_SEED = (
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
    "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
)


def test_mnemonic_to_seed_matches_bip39_vector() -> None:
    """Mnemonic to seed must reproduce the official BIP39 test vector."""
    seed = mnemonic_to_seed(REFERENCE_MNEMONIC, passphrase="TREZOR")

    assert seed.hex() == REFERENCE_SEED


def test_validate_mnemonic_detects_invalid_word() -> None:
    """An unknown word should result in validation failure."""
    invalid_phrase = REFERENCE_MNEMONIC.replace("about", "ab0ut")

    assert validate_mnemonic(invalid_phrase) is False


def test_mnemonic_to_entropy_invalid_checksum() -> None:
    """Changing the final word should trigger a checksum error."""
    altered_phrase = REFERENCE_MNEMONIC.replace("about", "absorb")

    with pytest.raises(InvalidMnemonicError):
        mnemonic_to_entropy(altered_phrase)


def test_generate_mnemonic_default_length() -> None:
    """Generated mnemonics should produce 12-word phrases by default."""
    mnemonic = generate_mnemonic()

    assert len(mnemonic.split()) == 12
    assert validate_mnemonic(mnemonic) is True
