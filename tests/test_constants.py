#!/usr/bin/env python3
"""
Test suite for the constants module.
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Util.constants import (
    BIP39_WORD_LIST,
    BIP44_COIN_TYPES,
    SECP256K1_N,
    SECP256K1_P,
    BASE58_ALPHABET,
    VALID_MNEMONIC_LENGTHS,
    PBKDF2_ITERATIONS,
    ADDRESS_VERSIONS
)


class TestConstants(unittest.TestCase):
    """Test cases for constants validation."""

    def test_bip39_word_list(self):
        """Test BIP39 word list properties."""
        self.assertEqual(len(BIP39_WORD_LIST), 2048)
        self.assertIsInstance(BIP39_WORD_LIST, tuple)
        self.assertIn('abandon', BIP39_WORD_LIST)
        self.assertIn('zoo', BIP39_WORD_LIST)
        
        # Test all words are lowercase
        for word in BIP39_WORD_LIST:
            self.assertEqual(word, word.lower())
        
        # Test no duplicates
        self.assertEqual(len(set(BIP39_WORD_LIST)), len(BIP39_WORD_LIST))

    def test_bip44_coin_types(self):
        """Test BIP44 coin types."""
        self.assertIsInstance(BIP44_COIN_TYPES, dict)
        self.assertGreater(len(BIP44_COIN_TYPES), 10)
        
        # Test specific coin types
        self.assertEqual(BIP44_COIN_TYPES['bitcoin'], 0)
        self.assertEqual(BIP44_COIN_TYPES['ethereum'], 60)
        self.assertEqual(BIP44_COIN_TYPES['litecoin'], 2)

    def test_secp256k1_constants(self):
        """Test secp256k1 curve constants."""
        self.assertIsInstance(SECP256K1_N, int)
        self.assertIsInstance(SECP256K1_P, int)
        self.assertGreater(SECP256K1_N, 0)
        self.assertGreater(SECP256K1_P, 0)

    def test_base58_alphabet(self):
        """Test Base58 alphabet."""
        self.assertEqual(len(BASE58_ALPHABET), 58)
        self.assertNotIn('0', BASE58_ALPHABET)  # No zero
        self.assertNotIn('O', BASE58_ALPHABET)  # No capital O
        self.assertNotIn('I', BASE58_ALPHABET)  # No capital I
        self.assertNotIn('l', BASE58_ALPHABET)  # No lowercase l

    def test_valid_mnemonic_lengths(self):
        """Test valid mnemonic lengths."""
        expected_lengths = [12, 15, 18, 21, 24]
        self.assertEqual(VALID_MNEMONIC_LENGTHS, expected_lengths)

    def test_pbkdf2_iterations(self):
        """Test PBKDF2 iterations."""
        self.assertEqual(PBKDF2_ITERATIONS, 2048)

    def test_address_versions(self):
        """Test address version constants."""
        self.assertIsInstance(ADDRESS_VERSIONS, dict)
        self.assertIn('bitcoin', ADDRESS_VERSIONS)
        self.assertIn('litecoin', ADDRESS_VERSIONS)
        
        # Test Bitcoin address versions
        btc_versions = ADDRESS_VERSIONS['bitcoin']
        self.assertEqual(btc_versions['p2pkh'], 0x00)
        self.assertEqual(btc_versions['p2sh'], 0x05)
        self.assertEqual(btc_versions['private'], 0x80)


if __name__ == '__main__':
    unittest.main() 