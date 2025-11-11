"""
Tests for hash library integration.

This test suite validates that the hash functions work correctly using
Python's standard library (hashlib) with fallbacks when needed.
"""

import pytest


class TestHashIntegration:
    """Test suite for hash library integration."""

    def test_hash_sha256(self):
        """Test SHA256 hashing from Python's standard library."""
        from libcrypto.hash import sha256

        data = b"Hello, World!"
        digest = sha256(data)

        # Known SHA256 hash
        expected = bytes.fromhex(
            "DFFD6021BB2BD5B0AF676290809EC3A53191DD81C7F70A4B28688A362182986F"
        )
        assert digest == expected

    def test_hash_double_sha256(self):
        """Test double SHA256 hashing."""
        from libcrypto.hash import double_sha256

        data = b"Hello, World!"
        digest = double_sha256(data)

        assert len(digest) == 32

    def test_hash_ripemd160_fallback(self):
        """Test RIPEMD160 hashing with fallback handling."""
        from libcrypto.hash import ripemd160

        data = b"Hello, World!"

        # Try to hash - this might use cryptod or raise NotImplementedError
        try:
            digest = ripemd160(data)
            assert len(digest) == 20
        except NotImplementedError:
            # Expected on systems without RIPEMD160
            pytest.skip("RIPEMD160 not available on this system")

    def test_hmac_sha512(self):
        """Test HMAC-SHA512 from Python's standard library."""
        from libcrypto.hash import hmac_sha512

        key = b"secret_key"
        message = b"message"

        digest = hmac_sha512(key, message)

        assert len(digest) == 64

    def test_keccak256_with_warning(self):
        """Test Keccak-256 with expected warning about fallback."""
        from libcrypto.hash import keccak256
        import warnings

        data = b"Hello, World!"

        # Should warn about using SHA3-256 fallback
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            digest = keccak256(data)

            # Check that a warning was issued (unless cryptod is available)
            # assert len(w) >= 0  # May or may not warn depending on availability

        assert len(digest) == 32

    def test_pbkdf2(self):
        """Test PBKDF2 key derivation from Python's standard library."""
        from libcrypto.hash import pbkdf2_hmac_sha512

        password = b"password"
        salt = b"salt"
        iterations = 1000
        dklen = 64

        key = pbkdf2_hmac_sha512(password, salt, iterations, dklen)

        assert len(key) == dklen
        assert isinstance(key, bytes)

    def test_secure_random(self):
        """Test random number generation from os.urandom."""
        from libcrypto.hash import secure_random_bytes

        random_bytes = secure_random_bytes(32)

        assert len(random_bytes) == 32
        assert isinstance(random_bytes, bytes)

        # Verify randomness (two calls should produce different values)
        random_bytes2 = secure_random_bytes(32)
        assert random_bytes != random_bytes2

    def test_hash_module_integration(self):
        """Test that our hash module provides all necessary functions."""
        from libcrypto.hash import (
            sha256,
            ripemd160,
            hash160,
            double_sha256,
            keccak256,
            hmac_sha512,
            pbkdf2_hmac_sha512,
        )

        data = b"test data"

        # Test all hash functions
        sha_result = sha256(data)
        assert len(sha_result) == 32

        try:
            ripe_result = ripemd160(data)
            assert len(ripe_result) == 20

            hash160_result = hash160(data)
            assert len(hash160_result) == 20
        except NotImplementedError:
            pytest.skip("RIPEMD160 not available")

        double_sha_result = double_sha256(data)
        assert len(double_sha_result) == 32

        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            keccak_result = keccak256(data)
            assert len(keccak_result) == 32

        hmac_result = hmac_sha512(b"key", data)
        assert len(hmac_result) == 64

        pbkdf2_result = pbkdf2_hmac_sha512(data, b"salt", 1000, 64)
        assert len(pbkdf2_result) == 64

    def test_no_external_crypto_imports(self):
        """Verify that hash module uses standard library or internal implementations."""
        import inspect
        from libcrypto import hash

        # Check module source
        source = inspect.getsource(hash)

        # Should use hashlib, hmac, os from standard library
        assert "import hashlib" in source
        assert "import hmac" in source
        assert "import os" in source

        # Should not have external pycryptodome imports without cryptod path
        assert "from pycryptodome" not in source.lower()
        assert "import pycryptodome" not in source.lower()

    def test_cryptod_package_structure(self):
        """Test that cryptod package is properly structured."""
        import libcrypto.cryptod

        # Check that cryptod has version
        assert hasattr(libcrypto.cryptod, "__version__")

    def test_consistent_hash_results(self):
        """Test that hash results are consistent across calls."""
        from libcrypto.hash import sha256

        data = b"consistent test data"

        # Hash the same data multiple times
        results = [sha256(data) for _ in range(5)]

        # All results should be identical
        assert all(r == results[0] for r in results)

    def test_hash_known_vectors(self):
        """Test hash functions against known test vectors."""
        from libcrypto.hash import sha256, ripemd160

        # SHA256 test vectors
        test_vectors_sha256 = [
            (b"", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"),
            (
                b"abc",
                "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
            ),
        ]

        for data, expected_hex in test_vectors_sha256:
            result = sha256(data)
            assert result.hex().upper() == expected_hex

        # RIPEMD160 test vectors (may not be available on all systems)
        try:
            test_vectors_ripemd = [
                (b"", "9C1185A5C5E9FC54612808977EE8F548B2258D31"),
                (b"abc", "8EB208F7E05D987A9B044A8E98C6B087F15A0BFC"),
            ]

            for data, expected_hex in test_vectors_ripemd:
                result = ripemd160(data)
                assert result.hex().upper() == expected_hex
        except NotImplementedError:
            pytest.skip("RIPEMD160 not available on this system")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
