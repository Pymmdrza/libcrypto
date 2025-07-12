#!/usr/bin/env python3
"""
Example usage of the cryptocorelib (libcrypto) library.

This example demonstrates:
1. BIP39 mnemonic generation and validation
2. Seed generation from mnemonics
3. Hash functions (SHA256, SHA512, etc.)
4. Basic wallet operations
5. Key generation and management

To run this example:
    python example.py
"""

import sys
import os

# Add the src directory to the path to import libcrypto
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from libcrypto.wallet.bip39 import BIP39, BIP39Error
    from libcrypto.Hash import SHA256, SHA512, MD5
    from libcrypto.Random import random
    from libcrypto.Util import Counter
    from libcrypto.Util.py3compat import tobytes, tostr
    
    print("✅ Successfully imported libcrypto modules!")
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're running this from the project root directory.")
    sys.exit(1)


def demo_bip39():
    """Demonstrate BIP39 mnemonic functionality."""
    print("\n" + "="*50)
    print("🔐 BIP39 MNEMONIC DEMONSTRATION")
    print("="*50)
    
    # Generate mnemonics of different lengths
    word_counts = [12, 15, 18, 21, 24]
    
    for word_count in word_counts:
        print(f"\n📝 Generating {word_count}-word mnemonic:")
        
        try:
            # Generate mnemonic
            mnemonic = BIP39.generate_mnemonic(word_count)
            print(f"   Mnemonic: {mnemonic}")
            
            # Validate mnemonic
            is_valid = BIP39.validate_mnemonic(mnemonic)
            print(f"   Valid: {is_valid}")
            
            # Generate seed from mnemonic
            seed = BIP39.mnemonic_to_seed(mnemonic, passphrase="test_passphrase")
            print(f"   Seed (first 32 bytes): {seed[:32].hex()}")
            
        except BIP39Error as e:
            print(f"   ❌ BIP39 Error: {e}")
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    # Test with invalid mnemonic
    print(f"\n🔍 Testing invalid mnemonic validation:")
    invalid_mnemonic = "invalid words that are not in bip39 wordlist"
    is_valid = BIP39.validate_mnemonic(invalid_mnemonic)
    print(f"   Invalid mnemonic valid: {is_valid}")


def demo_hashing():
    """Demonstrate hash functions."""
    print("\n" + "="*50)
    print("🔨 HASH FUNCTIONS DEMONSTRATION")
    print("="*50)
    
    test_data = b"Hello, Cryptocurrency World!"
    print(f"\nOriginal data: {test_data.decode()}")
    
    # SHA256
    sha256_hash = SHA256.new(test_data).digest()
    print(f"SHA256: {sha256_hash.hex()}")
    
    # SHA512
    sha512_hash = SHA512.new(test_data).digest()
    print(f"SHA512: {sha512_hash.hex()}")
    
    # MD5 (for demonstration - not recommended for security)
    md5_hash = MD5.new(test_data).digest()
    print(f"MD5: {md5_hash.hex()}")
    
    # Demonstrate hash update
    print(f"\n📝 Incremental hashing:")
    hasher = SHA256.new()
    hasher.update(b"Hello, ")
    hasher.update(b"Cryptocurrency ")
    hasher.update(b"World!")
    incremental_hash = hasher.digest()
    print(f"Incremental SHA256: {incremental_hash.hex()}")
    print(f"Same as direct hash: {incremental_hash.hex() == sha256_hash.hex()}")


def demo_random():
    """Demonstrate random number generation."""
    print("\n" + "="*50)
    print("🎲 RANDOM NUMBER GENERATION")
    print("="*50)
    
    # Generate random bytes
    random_bytes = random.get_random_bytes(32)
    print(f"Random 32 bytes: {random_bytes.hex()}")
    
    # Generate random integers
    random_int = random.getrandbits(256)
    print(f"Random 256-bit integer: {hex(random_int)}")
    
    # Generate multiple random values
    print(f"\n🔢 Multiple random values:")
    for i in range(5):
        rand_val = random.getrandbits(64)
        print(f"   Random {i+1}: {hex(rand_val)}")


def demo_counter():
    """Demonstrate Counter utility."""
    print("\n" + "="*50)
    print("🔢 COUNTER UTILITY DEMONSTRATION")
    print("="*50)
    
    # Create a counter
    counter = Counter.new(128, initial_value=0)
    print(f"Initial counter value: {counter().hex()}")
    
    # Increment counter several times
    for i in range(5):
        counter_val = counter()
        print(f"Counter {i+1}: {counter_val.hex()}")


def demo_utilities():
    """Demonstrate utility functions."""
    print("\n" + "="*50)
    print("🛠️ UTILITY FUNCTIONS DEMONSTRATION")
    print("="*50)
    
    # Test string/bytes conversion
    test_string = "Hello, World! 🌍"
    
    # Convert to bytes
    as_bytes = tobytes(test_string)
    print(f"String to bytes: {as_bytes}")
    
    # Convert back to string
    back_to_string = tostr(as_bytes)
    print(f"Bytes to string: {back_to_string}")
    
    # Test with different encodings
    hex_string = "48656c6c6f2c20576f726c6421"
    try:
        decoded = bytes.fromhex(hex_string)
        print(f"Hex decoded: {decoded.decode()}")
    except Exception as e:
        print(f"Hex decode error: {e}")


def main():
    """Main demonstration function."""
    print("🚀 CRYPTOCORELIB (LIBCRYPTO) LIBRARY EXAMPLES")
    print("=" * 60)
    print("This demonstration shows the main features of the library:")
    print("- BIP39 mnemonic generation and validation")
    print("- Cryptographic hash functions")
    print("- Random number generation")
    print("- Utility functions")
    
    try:
        # Run all demonstrations
        demo_bip39()
        demo_hashing()
        demo_random()
        demo_counter()
        demo_utilities()
        
        print("\n" + "="*60)
        print("✅ ALL DEMONSTRATIONS COMPLETED SUCCESSFULLY!")
        print("="*60)
        print("\n💡 Tips:")
        print("- Use BIP39 for mnemonic generation in wallet applications")
        print("- Always validate mnemonics before using them")
        print("- Use strong passphrases for additional security")
        print("- SHA256/SHA512 are recommended for cryptographic hashing")
        print("- Use the random module for cryptographically secure randomness")
        
    except Exception as e:
        print(f"\n❌ Error during demonstration: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main() 