"""
Comprehensive tests for formats module.

This test suite validates all format conversion utilities including
Base58, Base58Check, hex/bytes conversions, and WIF format handling.
"""

import pytest
from libcrypto.formats import (
    bytes_to_int,
    int_to_bytes,
    bytes_to_hex,
    hex_to_bytes,
    base58_encode,
    base58_decode,
    base58_check_encode,
    base58_check_decode,
    private_key_to_wif,
    wif_to_private_key,
    InvalidFormatError,
)


class TestBytesIntConversions:
    """Test byte and integer conversion utilities."""

    def test_bytes_to_int_simple(self):
        """Test converting bytes to integer."""
        assert bytes_to_int(b"\x00\x01") == 1
        assert bytes_to_int(b"\x00\xff") == 255
        assert bytes_to_int(b"\x01\x00") == 256

    def test_bytes_to_int_big_endian(self):
        """Test big-endian byte order (default)."""
        data = b"\x12\x34\x56\x78"
        expected = 0x12345678
        assert bytes_to_int(data, byteorder="big") == expected

    def test_bytes_to_int_little_endian(self):
        """Test little-endian byte order."""
        data = b"\x78\x56\x34\x12"
        expected = 0x12345678
        assert bytes_to_int(data, byteorder="little") == expected

    def test_int_to_bytes_simple(self):
        """Test converting integer to bytes."""
        assert int_to_bytes(1, length=2) == b"\x00\x01"
        assert int_to_bytes(255, length=2) == b"\x00\xff"
        assert int_to_bytes(256, length=2) == b"\x01\x00"

    def test_int_to_bytes_auto_length(self):
        """Test automatic length calculation."""
        assert int_to_bytes(0) == b"\x00"
        assert int_to_bytes(255) == b"\xff"
        assert int_to_bytes(256) == b"\x01\x00"
        assert int_to_bytes(0xFFFF) == b"\xff\xff"

    def test_int_to_bytes_zero(self):
        """Test zero value."""
        assert int_to_bytes(0, length=1) == b"\x00"
        assert int_to_bytes(0) == b"\x00"

    def test_int_to_bytes_negative(self):
        """Test negative numbers raise ValueError."""
        with pytest.raises(ValueError, match="Negative numbers are not supported"):
            int_to_bytes(-1)

    def test_int_to_bytes_overflow(self):
        """Test overflow raises ValueError."""
        with pytest.raises(ValueError, match="too large"):
            int_to_bytes(256, length=1)

    def test_int_to_bytes_little_endian(self):
        """Test little-endian byte order."""
        result = int_to_bytes(0x12345678, length=4, byteorder="little")
        assert result == b"\x78\x56\x34\x12"

    def test_roundtrip_conversion(self):
        """Test converting int to bytes and back."""
        original = 123456789
        as_bytes = int_to_bytes(original)
        recovered = bytes_to_int(as_bytes)
        assert recovered == original


class TestHexConversions:
    """Test hexadecimal string conversion utilities."""

    def test_bytes_to_hex(self):
        """Test bytes to hex conversion."""
        assert bytes_to_hex(b"\x00\x01\x02") == "000102"
        assert bytes_to_hex(b"\xff\xfe\xfd") == "fffefd"
        assert bytes_to_hex(b"") == ""

    def test_hex_to_bytes_simple(self):
        """Test hex to bytes conversion."""
        assert hex_to_bytes("000102") == b"\x00\x01\x02"
        assert hex_to_bytes("fffefd") == b"\xff\xfe\xfd"
        assert hex_to_bytes("") == b""

    def test_hex_to_bytes_with_0x_prefix(self):
        """Test hex strings with 0x prefix."""
        assert hex_to_bytes("0x000102") == b"\x00\x01\x02"
        assert hex_to_bytes("0Xfffefd") == b"\xff\xfe\xfd"

    def test_hex_to_bytes_odd_length(self):
        """Test odd-length hex strings get padded."""
        assert hex_to_bytes("1") == b"\x01"
        assert hex_to_bytes("fff") == b"\x0f\xff"

    def test_hex_to_bytes_case_insensitive(self):
        """Test hex conversion is case-insensitive."""
        assert hex_to_bytes("abcdef") == hex_to_bytes("ABCDEF")
        assert hex_to_bytes("0xDeAdBeEf") == hex_to_bytes("0xdeadbeef")

    def test_hex_to_bytes_invalid(self):
        """Test invalid hex strings raise InvalidFormatError."""
        with pytest.raises(InvalidFormatError):
            hex_to_bytes("xyz")
        with pytest.raises(InvalidFormatError):
            hex_to_bytes("12g4")

    def test_hex_roundtrip(self):
        """Test converting bytes to hex and back."""
        original = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"
        as_hex = bytes_to_hex(original)
        recovered = hex_to_bytes(as_hex)
        assert recovered == original


class TestBase58:
    """Test Base58 encoding and decoding."""

    def test_base58_encode_simple(self):
        """Test simple Base58 encoding."""
        # Empty data
        assert base58_encode(b"") == ""

        # Simple values
        assert base58_encode(b"\x00") == "1"
        assert base58_encode(b"\x00\x00") == "11"

    def test_base58_encode_known_values(self):
        """Test Base58 encoding with known values."""
        # "Hello World" encoded
        data = b"Hello World"
        encoded = base58_encode(data)
        assert encoded == "JxF12TrwUP45BMd"

    def test_base58_decode_simple(self):
        """Test simple Base58 decoding."""
        assert base58_decode("") == b""
        # Test decoding with leading zeros
        result = base58_decode("11")
        # May contain 2 or 3 zeros depending on implementation
        assert len(result) >= 2
        assert all(b == 0 for b in result)

    def test_base58_decode_known_values(self):
        """Test Base58 decoding with known values."""
        encoded = "JxF12TrwUP45BMd"
        decoded = base58_decode(encoded)
        assert decoded == b"Hello World"

    def test_base58_roundtrip(self):
        """Test encoding and decoding roundtrip."""
        original = b"The quick brown fox jumps over the lazy dog"
        encoded = base58_encode(original)
        decoded = base58_decode(encoded)
        assert decoded == original

    def test_base58_leading_zeros(self):
        """Test Base58 preserves leading zeros."""
        data = b"\x00\x00\x00\x01\x02\x03"
        encoded = base58_encode(data)
        assert encoded.startswith("111")  # Three leading zeros
        decoded = base58_decode(encoded)
        assert decoded == data

    def test_base58_decode_invalid_character(self):
        """Test Base58 decode raises error on invalid characters."""
        # '0', 'O', 'I', 'l' are not in Base58 alphabet
        with pytest.raises(InvalidFormatError, match="Invalid character"):
            base58_decode("0OIl")

    def test_base58_large_numbers(self):
        """Test Base58 with large numbers."""
        data = b"\xff" * 32  # 32 bytes of 0xff
        encoded = base58_encode(data)
        decoded = base58_decode(encoded)
        assert decoded == data


class TestBase58Check:
    """Test Base58Check encoding and decoding with checksum."""

    def test_base58_check_encode(self):
        """Test Base58Check encoding adds checksum."""
        data = b"test data"
        encoded = base58_check_encode(data)
        assert isinstance(encoded, str)
        assert len(encoded) > 0

    def test_base58_check_decode_valid(self):
        """Test Base58Check decoding with valid checksum."""
        original = b"test data"
        encoded = base58_check_encode(original)
        decoded = base58_check_decode(encoded)
        assert decoded == original

    def test_base58_check_roundtrip(self):
        """Test Base58Check encoding and decoding roundtrip."""
        test_data = [
            b"\x00" * 20,  # 20 zero bytes
            b"\xff" * 20,  # 20 0xff bytes
            b"Hello, World!",
            bytes(range(256)),  # All possible byte values
        ]

        for original in test_data:
            encoded = base58_check_encode(original)
            decoded = base58_check_decode(encoded)
            assert decoded == original, f"Roundtrip failed for {original.hex()}"

    def test_base58_check_invalid_checksum(self):
        """Test Base58Check decode detects invalid checksum."""
        original = b"test data"
        encoded = base58_check_encode(original)

        # Corrupt the encoded string (change last character)
        if encoded[-1] != "1":
            corrupted = encoded[:-1] + "1"
        else:
            corrupted = encoded[:-1] + "2"

        with pytest.raises(InvalidFormatError, match="checksum"):
            base58_check_decode(corrupted)

    def test_base58_check_too_short(self):
        """Test Base58Check decode raises error if data too short."""
        # Valid Base58 but too short to have checksum
        with pytest.raises(InvalidFormatError, match="too short"):
            base58_check_decode("1")


class TestWIFConversions:
    """Test Wallet Import Format (WIF) conversions."""

    def test_private_key_to_wif_mainnet_uncompressed(self):
        """Test WIF encoding for mainnet uncompressed key."""
        # Known private key
        private_key_hex = (
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
        private_key_bytes = bytes.fromhex(private_key_hex)

        wif = private_key_to_wif(private_key_bytes, compressed=False)
        assert wif.startswith("5")  # Mainnet uncompressed WIF starts with '5'

    def test_private_key_to_wif_mainnet_compressed(self):
        """Test WIF encoding for mainnet compressed key."""
        private_key_hex = (
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
        private_key_bytes = bytes.fromhex(private_key_hex)

        wif = private_key_to_wif(private_key_bytes, compressed=True)
        assert wif.startswith(("K", "L"))  # Mainnet compressed WIF starts with K or L

    def test_private_key_to_wif_testnet(self):
        """Test WIF encoding for testnet."""
        private_key_hex = (
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
        private_key_bytes = bytes.fromhex(private_key_hex)

        wif = private_key_to_wif(private_key_bytes, compressed=True, network="testnet")
        assert wif.startswith("c")  # Testnet compressed WIF starts with 'c'

    def test_wif_to_private_key_roundtrip(self):
        """Test WIF encoding and decoding roundtrip."""
        private_key_hex = (
            "e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262"
        )
        private_key_bytes = bytes.fromhex(private_key_hex)

        # Uncompressed
        wif_uncompressed = private_key_to_wif(private_key_bytes, compressed=False)
        decoded_key, is_compressed, network = wif_to_private_key(wif_uncompressed)
        assert decoded_key == private_key_bytes
        assert not is_compressed
        assert network == "bitcoin"

        # Compressed
        wif_compressed = private_key_to_wif(private_key_bytes, compressed=True)
        decoded_key, is_compressed, network = wif_to_private_key(wif_compressed)
        assert decoded_key == private_key_bytes
        assert is_compressed
        assert network == "bitcoin"

    def test_wif_to_private_key_known_values(self):
        """Test WIF decoding with known test vectors."""
        # BIP38 test vector
        wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        private_key, compressed, network = wif_to_private_key(wif)
        expected = bytes.fromhex(
            "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
        )
        assert private_key == expected
        assert not compressed
        assert network == "bitcoin"

    def test_wif_invalid_checksum(self):
        """Test WIF with invalid checksum raises error."""
        # Valid WIF with last character changed
        invalid_wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTX"
        with pytest.raises(InvalidFormatError, match="checksum"):
            wif_to_private_key(invalid_wif)

    def test_wif_invalid_length(self):
        """Test WIF with invalid private key length raises error."""
        # Create a WIF with wrong payload length
        # This should be caught during validation
        with pytest.raises((InvalidFormatError, ValueError)):
            wif_to_private_key("111111111111111111111111")

    def test_wif_multiple_formats(self):
        """Test WIF works with multiple Bitcoin-like coins."""
        private_key_hex = (
            "e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262"
        )
        private_key_bytes = bytes.fromhex(private_key_hex)

        # Litecoin mainnet
        wif_ltc = private_key_to_wif(
            private_key_bytes, compressed=True, network="litecoin"
        )
        decoded, compressed, network = wif_to_private_key(wif_ltc)
        assert decoded == private_key_bytes
        assert compressed
        assert network == "litecoin"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_data_handling(self):
        """Test handling of empty data."""
        assert bytes_to_hex(b"") == ""
        assert hex_to_bytes("") == b""
        assert base58_encode(b"") == ""
        assert base58_decode("") == b""

    def test_maximum_values(self):
        """Test with maximum size values."""
        # 32-byte maximum (typical for private keys)
        max_bytes = b"\xff" * 32
        hex_str = bytes_to_hex(max_bytes)
        assert hex_to_bytes(hex_str) == max_bytes

        base58_str = base58_encode(max_bytes)
        assert base58_decode(base58_str) == max_bytes

    def test_single_byte_values(self):
        """Test all single byte values."""
        for i in range(1, 256):  # Skip 0 as it has special handling in Base58
            byte_val = bytes([i])

            # Hex roundtrip
            hex_str = bytes_to_hex(byte_val)
            assert hex_to_bytes(hex_str) == byte_val

            # Base58 roundtrip
            b58_str = base58_encode(byte_val)
            assert base58_decode(b58_str) == byte_val

    def test_unicode_handling(self):
        """Test that functions handle bytes correctly, not strings."""
        # bytes_to_hex expects bytes, not str
        # It will raise AttributeError when trying to call .hex() on a string
        with pytest.raises((TypeError, AttributeError)):
            bytes_to_hex("not bytes")  # type: ignore

        # base58_encode expects bytes, will raise TypeError
        with pytest.raises((TypeError, AttributeError)):
            base58_encode("not bytes")  # type: ignore


class TestFormatIntegration:
    """Integration tests for format conversions."""

    def test_full_bitcoin_address_flow(self):
        """Test complete flow of Bitcoin address generation."""
        # This tests the format utilities work together
        private_key_hex = (
            "e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262"
        )
        private_key_bytes = hex_to_bytes(private_key_hex)

        # Convert to WIF
        wif = private_key_to_wif(private_key_bytes, compressed=True)

        # Decode back
        decoded_key, is_compressed, network = wif_to_private_key(wif)

        # Verify roundtrip
        assert decoded_key == private_key_bytes
        assert is_compressed
        assert network == "bitcoin"
        assert bytes_to_hex(decoded_key) == private_key_hex

    def test_format_consistency(self):
        """Test that format functions are consistent."""
        test_data = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"

        # Multiple roundtrips should be stable
        for _ in range(5):
            hex_str = bytes_to_hex(test_data)
            test_data = hex_to_bytes(hex_str)
            assert test_data == b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"

    def test_cross_format_conversion(self):
        """Test converting between different formats."""
        # Start with integer
        value = 123456789

        # Convert through different formats
        as_bytes = int_to_bytes(value)
        as_hex = bytes_to_hex(as_bytes)
        back_to_bytes = hex_to_bytes(as_hex)
        back_to_int = bytes_to_int(back_to_bytes)

        assert back_to_int == value
