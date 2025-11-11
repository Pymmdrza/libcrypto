"""
Tests for cryptographic constants.

This test suite validates that all constants are correctly defined
and have the expected values.
"""

import pytest
from libcrypto.constants import (
    SECP256K1_P,
    SECP256K1_N,
    SECP256K1_GX,
    SECP256K1_GY,
    SECP256K1_A,
    SECP256K1_B,
    MAX_PRIVATE_KEY,
    BASE58_ALPHABET,
    ADDRESS_VERSIONS,
)


class TestSecp256k1Constants:
    """Test secp256k1 curve constants."""

    def test_secp256k1_p_value(self):
        """Test that secp256k1 prime field modulus is correct."""
        expected_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        assert SECP256K1_P == expected_p

    def test_secp256k1_n_value(self):
        """Test that secp256k1 order is correct."""
        expected_n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        assert SECP256K1_N == expected_n

    def test_secp256k1_generator_x(self):
        """Test that generator point X coordinate is correct."""
        expected_gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        assert SECP256K1_GX == expected_gx

    def test_secp256k1_generator_y(self):
        """Test that generator point Y coordinate is correct."""
        expected_gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        assert SECP256K1_GY == expected_gy

    def test_secp256k1_curve_a(self):
        """Test that curve parameter a is correct."""
        assert SECP256K1_A == 0

    def test_secp256k1_curve_b(self):
        """Test that curve parameter b is correct."""
        assert SECP256K1_B == 7

    def test_max_private_key(self):
        """Test that maximum private key is N-1."""
        assert MAX_PRIVATE_KEY == SECP256K1_N - 1

    def test_generator_on_curve(self):
        """Test that generator point is on the curve."""
        # Verify: y^2 = x^3 + 7 (mod p)
        y_squared = (SECP256K1_GY * SECP256K1_GY) % SECP256K1_P
        x_cubed_plus_7 = (pow(SECP256K1_GX, 3, SECP256K1_P) + SECP256K1_B) % SECP256K1_P
        assert y_squared == x_cubed_plus_7

    def test_n_less_than_p(self):
        """Test that order N is less than prime P."""
        assert SECP256K1_N < SECP256K1_P

    def test_constants_are_integers(self):
        """Test that all constants are integers."""
        assert isinstance(SECP256K1_P, int)
        assert isinstance(SECP256K1_N, int)
        assert isinstance(SECP256K1_GX, int)
        assert isinstance(SECP256K1_GY, int)
        assert isinstance(SECP256K1_A, int)
        assert isinstance(SECP256K1_B, int)


class TestBase58Alphabet:
    """Test Base58 alphabet constant."""

    def test_base58_alphabet_length(self):
        """Test that Base58 alphabet has 58 characters."""
        assert len(BASE58_ALPHABET) == 58

    def test_base58_alphabet_unique(self):
        """Test that all Base58 characters are unique."""
        assert len(set(BASE58_ALPHABET)) == 58

    def test_base58_excludes_confusing_chars(self):
        """Test that Base58 excludes confusing characters."""
        # Base58 excludes 0, O, I, l
        assert "0" not in BASE58_ALPHABET
        assert "O" not in BASE58_ALPHABET
        assert "I" not in BASE58_ALPHABET
        assert "l" not in BASE58_ALPHABET

    def test_base58_alphabet_value(self):
        """Test the exact Base58 alphabet."""
        expected = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        assert BASE58_ALPHABET == expected


class TestAddressVersions:
    """Test address version constants."""

    def test_bitcoin_versions_present(self):
        """Test that Bitcoin versions are defined."""
        assert "bitcoin" in ADDRESS_VERSIONS
        assert "p2pkh" in ADDRESS_VERSIONS["bitcoin"]
        assert "p2sh" in ADDRESS_VERSIONS["bitcoin"]
        assert "private" in ADDRESS_VERSIONS["bitcoin"]

    def test_bitcoin_p2pkh_version(self):
        """Test Bitcoin P2PKH version byte."""
        assert ADDRESS_VERSIONS["bitcoin"]["p2pkh"] == 0x00

    def test_bitcoin_p2sh_version(self):
        """Test Bitcoin P2SH version byte."""
        assert ADDRESS_VERSIONS["bitcoin"]["p2sh"] == 0x05

    def test_bitcoin_private_version(self):
        """Test Bitcoin private key version byte."""
        assert ADDRESS_VERSIONS["bitcoin"]["private"] == 0x80

    def test_testnet_versions_present(self):
        """Test that testnet versions are defined."""
        assert "testnet" in ADDRESS_VERSIONS
        assert ADDRESS_VERSIONS["testnet"]["p2pkh"] == 0x6F
        assert ADDRESS_VERSIONS["testnet"]["p2sh"] == 0xC4

    def test_altcoins_present(self):
        """Test that altcoin versions are defined."""
        assert "litecoin" in ADDRESS_VERSIONS
        assert "dogecoin" in ADDRESS_VERSIONS
        assert "dash" in ADDRESS_VERSIONS

    def test_all_versions_are_integers(self):
        """Test that all version bytes are integers."""
        for network, versions in ADDRESS_VERSIONS.items():
            for version_type, version_byte in versions.items():
                assert isinstance(version_byte, int)
                assert 0 <= version_byte <= 255


class TestConstantsImmutability:
    """Test that constants behave as expected."""

    def test_constants_exist(self):
        """Test that all required constants exist."""
        required_constants = [
            "SECP256K1_P",
            "SECP256K1_N",
            "SECP256K1_GX",
            "SECP256K1_GY",
            "SECP256K1_A",
            "SECP256K1_B",
            "MAX_PRIVATE_KEY",
            "BASE58_ALPHABET",
            "ADDRESS_VERSIONS",
        ]

        import libcrypto.constants as const_module

        for const_name in required_constants:
            assert hasattr(const_module, const_name)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
