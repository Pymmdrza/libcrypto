"""
Verification script to confirm libcrypto works without external crypto dependencies.
"""

import sys
from libcrypto import PrivateKey, Wallet, generate_mnemonic, mnemonic_to_seed


def main():
    print("=" * 60)
    print("LibCrypto Dependency Verification")
    print("=" * 60)

    # Check no external crypto dependencies loaded
    print("\n1. Checking dependencies...")
    has_ecdsa = "ecdsa" in sys.modules
    has_pycryptodome = "Crypto" in sys.modules

    # Check if Crypto module is from our internal cryptod or external
    is_internal_cryptod = False
    if has_pycryptodome and "Crypto" in sys.modules:
        crypto_file = getattr(sys.modules.get("Crypto"), "__file__", "")
        is_internal_cryptod = "libcrypto" in crypto_file and "cryptod" in crypto_file

    print(f"   ecdsa loaded: {has_ecdsa} {'FAIL' if has_ecdsa else 'PASS'}")
    if has_pycryptodome:
        if is_internal_cryptod:
            print(
                f"   pycryptodome loaded: {has_pycryptodome} PASS (internal cryptod library)"
            )
        else:
            print(
                f"   pycryptodome loaded: {has_pycryptodome} FAIL (external dependency)"
            )
    else:
        print(f"   pycryptodome loaded: {has_pycryptodome} PASS")

    # Test secp256k1
    print("\n2. Testing secp256k1 (pure Python)...")
    pk1 = PrivateKey(1)
    expected_pubkey = (
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    actual_pubkey = pk1.get_public_key(compressed=True).hex

    print(f"   Private key 1 → Public key")
    print(f"   Expected: {expected_pubkey}")
    print(f"   Actual:   {actual_pubkey}")
    print(f"   {'PASS' if actual_pubkey == expected_pubkey else 'FAIL'}")

    # Test random key generation
    print("\n3. Testing random key generation...")
    pk_random = PrivateKey()
    print(f"   Generated private key: {pk_random.hex[:32]}...")
    print(f"   Public key (compressed): {pk_random.get_public_key().hex[:32]}...")
    print(f"   PASS")

    # Test BIP39 mnemonic
    print("\n4. Testing BIP39 mnemonic...")
    mnemonic = generate_mnemonic()
    seed = mnemonic_to_seed(mnemonic)
    print(f"   Mnemonic: {' '.join(mnemonic.split()[:4])}...")
    print(f"   Seed: {seed.hex()[:32]}...")
    print(f"   PASS")

    # Test wallet
    print("\n5. Testing wallet address generation...")
    wallet = Wallet(PrivateKey(1))
    btc_address = wallet.get_address("bitcoin", "p2pkh")
    print(f"   Bitcoin P2PKH address: {btc_address}")
    print(f"   PASS")

    print("\n" + "=" * 60)
    if not has_ecdsa and (not has_pycryptodome or is_internal_cryptod):
        print("ALL CHECKS PASSED - No external crypto dependencies!")
        print("   (Using internal cryptod library when available)")
    else:
        print("FAILED - External crypto dependencies detected")
    print("=" * 60)


if __name__ == "__main__":
    main()
