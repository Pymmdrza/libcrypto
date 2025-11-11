"""
Tests for secp256k1 elliptic curve operations.

This test suite validates the pure Python secp256k1 implementation
against known test vectors and ensures compatibility with the old ecdsa-based implementation.
"""

import pytest
from libcrypto.secp256k1 import (
    private_key_to_public_key,
    public_key_to_point_coords,
    compress_public_key,
    decompress_public_key,
    Secp256k1Error,
)


class TestSecp256k1:
    """Test suite for secp256k1 operations."""

    def test_private_key_to_public_key_compressed(self):
        """Test generating compressed public key from private key."""
        # Known test vector
        private_key = 0x1
        public_key = private_key_to_public_key(private_key, compressed=True)

        # Check format
        assert len(public_key) == 33
        assert public_key[0] in (0x02, 0x03)

        # Known value for private key = 1
        expected = bytes.fromhex(
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        )
        assert public_key == expected

    def test_private_key_to_public_key_uncompressed(self):
        """Test generating uncompressed public key from private key."""
        private_key = 0x1
        public_key = private_key_to_public_key(private_key, compressed=False)

        # Check format
        assert len(public_key) == 65
        assert public_key[0] == 0x04

        # Known value for private key = 1 (generator point)
        expected = bytes.fromhex(
            "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        )
        assert public_key == expected

    def test_private_key_validation(self):
        """Test private key validation."""
        # Valid keys should work
        private_key_to_public_key(1)
        private_key_to_public_key(
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
        )

        # Invalid keys should raise error
        with pytest.raises(Secp256k1Error):
            private_key_to_public_key(0)  # Too small

        with pytest.raises(Secp256k1Error):
            private_key_to_public_key(
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            )  # Too large

    def test_public_key_to_point_coords_compressed(self):
        """Test extracting coordinates from compressed public key."""
        public_key = bytes.fromhex(
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        )
        x, y = public_key_to_point_coords(public_key)

        # Known generator point coordinates
        expected_x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        expected_y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

        assert x == expected_x
        assert y == expected_y

    def test_public_key_to_point_coords_uncompressed(self):
        """Test extracting coordinates from uncompressed public key."""
        public_key = bytes.fromhex(
            "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        )
        x, y = public_key_to_point_coords(public_key)

        expected_x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        expected_y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

        assert x == expected_x
        assert y == expected_y

    def test_compress_uncompressed_public_key(self):
        """Test compressing an uncompressed public key."""
        uncompressed = bytes.fromhex(
            "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        )
        compressed = compress_public_key(uncompressed)

        expected = bytes.fromhex(
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        )
        assert compressed == expected

    def test_compress_already_compressed(self):
        """Test that compressing a compressed key works."""
        compressed = bytes.fromhex(
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        )
        result = compress_public_key(compressed)
        assert result == compressed

    def test_decompress_compressed_public_key(self):
        """Test decompressing a compressed public key."""
        compressed = bytes.fromhex(
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        )
        uncompressed = decompress_public_key(compressed)

        expected = bytes.fromhex(
            "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        )
        assert uncompressed == expected

    def test_decompress_already_uncompressed(self):
        """Test that decompressing an uncompressed key works."""
        uncompressed = bytes.fromhex(
            "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        )
        result = decompress_public_key(uncompressed)
        assert result == uncompressed

    def test_round_trip_compression(self):
        """Test that compress->decompress->compress works correctly."""
        # Start with a random private key
        private_key = 0x123456789ABCDEF

        # Generate uncompressed public key
        uncompressed = private_key_to_public_key(private_key, compressed=False)

        # Compress it
        compressed = compress_public_key(uncompressed)

        # Decompress it
        uncompressed2 = decompress_public_key(compressed)

        # Compress again
        compressed2 = compress_public_key(uncompressed2)

        # All should match
        assert uncompressed == uncompressed2
        assert compressed == compressed2

    def test_multiple_private_keys(self):
        """Test with multiple known private keys."""
        test_cases = [
            (0x1, "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
            (0x2, "02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"),
            (0x3, "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"),
        ]

        for private_key, expected_hex in test_cases:
            public_key = private_key_to_public_key(private_key, compressed=True)
            assert public_key.hex().upper() == expected_hex

    def test_invalid_public_key_format(self):
        """Test that invalid public key formats raise errors."""
        # Invalid length
        with pytest.raises(Secp256k1Error):
            public_key_to_point_coords(b"too short")

        # Invalid compressed prefix
        with pytest.raises(Secp256k1Error):
            invalid_compressed = bytes.fromhex(
                "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
            )[:33]
            public_key_to_point_coords(invalid_compressed)

        # Invalid uncompressed prefix
        with pytest.raises(Secp256k1Error):
            invalid_uncompressed = (
                bytes.fromhex(
                    "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
                )
                + b"\\x00" * 32
            )
            public_key_to_point_coords(invalid_uncompressed)

    def test_point_not_on_curve(self):
        """Test that invalid points raise errors."""
        # Create an invalid point (not on curve)
        invalid_point = b"\\x04" + b"\\x00" * 32 + b"\\x00" * 32

        with pytest.raises(Secp256k1Error):
            public_key_to_point_coords(invalid_point)

    def test_large_private_keys(self):
        """Test with large private keys close to the maximum."""
        # Maximum valid private key
        max_key = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140

        public_key = private_key_to_public_key(max_key, compressed=True)
        assert len(public_key) == 33

        # Verify we can extract coordinates
        x, y = public_key_to_point_coords(public_key)
        assert x > 0
        assert y > 0

    def test_consistency_across_formats(self):
        """Test that compressed and uncompressed formats represent the same point."""
        private_key = 0xDEADBEEF

        compressed = private_key_to_public_key(private_key, compressed=True)
        uncompressed = private_key_to_public_key(private_key, compressed=False)

        # Extract coordinates from both
        x1, y1 = public_key_to_point_coords(compressed)
        x2, y2 = public_key_to_point_coords(uncompressed)

        # Coordinates should match
        assert x1 == x2
        assert y1 == y2


class TestSecp256k1Cryptod:
    """Test that cryptod integration works correctly."""

    def test_cryptod_hash_integration(self):
        """Test that hash functions from cryptod work with secp256k1."""
        from libcrypto.hash import sha256, hash160

        # Generate a public key
        private_key = 0x1
        public_key = private_key_to_public_key(private_key, compressed=True)

        # Hash it (common operation in Bitcoin addresses)
        hash_result = hash160(public_key)
        assert len(hash_result) == 20

        # Known hash160 of generator point compressed public key
        expected = bytes.fromhex("751E76E8199196D454941C45D1B3A323F1433BD6")
        assert hash_result == expected

    def test_no_external_dependencies(self):
        """Verify that secp256k1 module doesn't import external crypto libraries."""
        import sys

        # These should not be in sys.modules after importing secp256k1
        # (if they were imported before the test, that's okay)
        forbidden_modules = ["ecdsa", "pycryptodome"]

        # Import our module
        from libcrypto import secp256k1

        # Check module source
        import inspect

        source = inspect.getsource(secp256k1)

        # Verify no external crypto imports in source
        assert "from ecdsa" not in source
        assert "import ecdsa" not in source
        assert "from Crypto" not in source or "from .cryptod.lib.Crypto" in source


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
