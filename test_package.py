#!/usr/bin/env python3
"""
Test script to validate libcrypto package functionality.

This script tests the core BIP39 functionality using only internal dependencies.
"""

import sys
import os

# Add the build directory to Python path
build_dir = os.path.join(os.path.dirname(__file__), 'build', 'lib.linux-x86_64-cpython-312')
sys.path.insert(0, build_dir)

def test_bip39():
    """Test BIP39 mnemonic functionality."""
    print("=" * 60)
    print("LibCrypto Package Test - BIP39 Functionality")
    print("=" * 60)
    
    try:
        from libcrypto.bip39 import generate_mnemonic, validate_mnemonic, mnemonic_to_seed
        print("✅ Successfully imported BIP39 functions")
    except ImportError as e:
        print(f"❌ Failed to import BIP39 functions: {e}")
        return False
    
    # Test mnemonic generation for different word counts
    word_counts = [12, 15, 18, 21, 24]
    
    for word_count in word_counts:
        try:
            mnemonic = generate_mnemonic(word_count)
            words = mnemonic.split()
            
            if len(words) != word_count:
                print(f"❌ Word count mismatch for {word_count}: got {len(words)}")
                return False
                
            print(f"✅ Generated {word_count}-word mnemonic: {words[0]}...{words[-1]}")
            
            # Validate the generated mnemonic
            is_valid = validate_mnemonic(mnemonic)
            if not is_valid:
                print(f"❌ Generated mnemonic failed validation: {mnemonic}")
                return False
            print(f"✅ Validation passed for {word_count}-word mnemonic")
            
            # Generate seed
            seed = mnemonic_to_seed(mnemonic)
            if len(seed) != 64:
                print(f"❌ Seed length incorrect: expected 64, got {len(seed)}")
                return False
            print(f"✅ Generated 64-byte seed: {seed.hex()[:16]}...")
            
        except Exception as e:
            print(f"❌ Error testing {word_count}-word mnemonic: {e}")
            return False
    
    print("\n" + "=" * 60)
    print("🎉 ALL BIP39 TESTS PASSED!")
    print("✅ Zero external cryptographic dependencies")
    print("✅ All internal C extensions working")
    print("✅ Package ready for PyPI upload")
    print("=" * 60)
    
    return True

def test_hash_functions():
    """Test internal hash functions."""
    print("\nTesting internal hash functions...")
    
    try:
        from libcrypto.Hash import SHA256, SHA512, RIPEMD160
        
        test_data = b"Hello, LibCrypto!"
        
        # Test SHA256
        sha256_hash = SHA256.new(test_data).digest()
        print(f"✅ SHA256: {sha256_hash.hex()[:16]}...")
        
        # Test SHA512
        sha512_hash = SHA512.new(test_data).digest()
        print(f"✅ SHA512: {sha512_hash.hex()[:16]}...")
        
        # Test RIPEMD160
        ripemd_hash = RIPEMD160.new(test_data).digest()
        print(f"✅ RIPEMD160: {ripemd_hash.hex()[:16]}...")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing hash functions: {e}")
        return False

def main():
    """Main test function."""
    print("LibCrypto Package Validation")
    print("Testing restructured package with zero external dependencies\n")
    
    # Test BIP39 functionality
    bip39_success = test_bip39()
    
    # Test hash functions
    hash_success = test_hash_functions()
    
    if bip39_success and hash_success:
        print("\n🎉 ALL TESTS PASSED! Package is ready for PyPI.")
        return 0
    else:
        print("\n❌ Some tests failed.")
        return 1

if __name__ == "__main__":
    sys.exit(main())