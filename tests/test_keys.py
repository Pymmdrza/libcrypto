"""Tests for `libcrypto.keys` utility classes."""
from __future__ import annotations

import pytest

from libcrypto.keys import KeyError, PrivateKey, PublicKey
from libcrypto.formats import wif_to_private_key, InvalidFormatError


def test_private_key_wif_roundtrip(deterministic_private_key_hex: str) -> None:
    """PrivateKey should round-trip through WIF with compression preserved."""
    key = PrivateKey(deterministic_private_key_hex)
    wif = key.to_wif(compressed=True)

    key_bytes, is_compressed, network = wif_to_private_key(wif)

    assert key_bytes.hex() == deterministic_private_key_hex
    assert is_compressed is True
    assert network == "bitcoin"


def test_private_key_invalid_hex_length() -> None:
    """Creating a private key with invalid hex length must raise KeyError."""
    with pytest.raises(KeyError):
        PrivateKey("deadbeef")


def test_wif_to_private_key_invalid_checksum() -> None:
    """wif_to_private_key should raise when checksum is incorrect."""
    invalid_wif = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDg"  # altered last char
    with pytest.raises(InvalidFormatError):
        wif_to_private_key(invalid_wif)


def test_public_key_enforces_length() -> None:
    """PublicKey rejects byte sequences of unsupported length."""
    with pytest.raises(KeyError):
        PublicKey(b"\x02" * 10)


def test_public_key_compression_roundtrip(deterministic_private_key_hex: str) -> None:
    """Compression toggling should preserve public key material."""
    private_key = PrivateKey(deterministic_private_key_hex)
    compressed = private_key.get_public_key(compressed=True)
    uncompressed = compressed.to_uncompressed()

    assert uncompressed.compressed is False
    assert compressed.to_uncompressed().to_compressed().hex == compressed.hex
