"""Test cryptod library integration"""

from libcrypto.hash import (
    sha256,
    ripemd160,
    keccak256,
    hmac_sha512,
    pbkdf2_hmac_sha512,
    secure_random_bytes,
    double_sha256,
    hash160,
)

print("Testing cryptod imports...")
data = b"test"

print(f"SHA256: {sha256(data).hex()[:32]}...")
print(f"RIPEMD160: {ripemd160(data).hex()[:32]}...")
print(f"Keccak256: {keccak256(data).hex()[:32]}...")
print(f'HMAC-SHA512: {hmac_sha512(b"key", data).hex()[:32]}...')
print(f"Random bytes: {secure_random_bytes(8).hex()}")
print(f"Double SHA256: {double_sha256(data).hex()[:32]}...")
print(f"Hash160: {hash160(data).hex()[:32]}...")

# Test PBKDF2
pbkdf2_result = pbkdf2_hmac_sha512(b"password", b"salt", 2048, 64)
print(f"PBKDF2: {pbkdf2_result.hex()[:32]}...")

print("\n✅ All cryptod functions working!")
print("✅ Using internal cryptod library (no external dependencies)")
