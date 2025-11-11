# all_examples.py

from libcrypto import (
    # High-level interface
    Wallet,
    # HD Wallet components
    HDWallet,
    generate_mnemonic,
    validate_mnemonic,
    mnemonic_to_seed,
    # Low-level components
    PrivateKey,
    PublicKey,
    # Utility functions
    wif_to_private_key,
)

# This sample private key is for demonstration purposes only.
# DO NOT USE THIS KEY FOR REAL ASSETS.
SAMPLE_KEY_HEX = "dafef72127c55a5a482aceb07eb13c62104ecd30957034806e224e38cf111e1b"
SAMPLE_KEY_WIF = "L4ZQks37JHUadEqaj2nGB1eaZFcsRZwZGQ7WVYuQiztzg4pqopU6"


# --- 1. Using the High-Level Wallet Class ---
# This is the recommended way for most use cases.

print("--- 1. Wallet Class Examples ---")

# Initialize the Wallet with a hex private key
wallet_from_hex = Wallet(SAMPLE_KEY_HEX)

# Generate addresses for various coins
p2pkh_btc = wallet_from_hex.get_address(coin="bitcoin", address_type="p2pkh")
p2sh_segwit_btc = wallet_from_hex.get_address(
    coin="bitcoin", address_type="p2sh-p2wpkh"
)
p2wpkh_btc = wallet_from_hex.get_address(coin="bitcoin", address_type="p2wpkh")
ethereum_address = wallet_from_hex.get_address(coin="ethereum")
dash_address = wallet_from_hex.get_address(coin="dash")
dogecoin_address = wallet_from_hex.get_address(coin="dogecoin")
tron_address = wallet_from_hex.get_address(coin="tron")
ripple_address = wallet_from_hex.get_address(coin="ripple")
litecoin_p2wpkh = wallet_from_hex.get_address(coin="litecoin", address_type="p2wpkh")
bch_address = wallet_from_hex.get_address(coin="bitcoin_cash", address_type="p2pkh")

print(f"Bitcoin P2PKH:          {p2pkh_btc}")
print(f"Bitcoin P2SH-SegWit:    {p2sh_segwit_btc}")
print(f"Bitcoin Native SegWit:  {p2wpkh_btc}")
print(f"Ethereum Address:       {ethereum_address}")
print(f"Dash Address:           {dash_address}")
print(f"Dogecoin Address:       {dogecoin_address}")
print(f"Tron Address:           {tron_address}")
print(f"Ripple Address:         {ripple_address}")
print(f"Litecoin Native SegWit: {litecoin_p2wpkh}")
print(f"Bitcoin Cash (P2PKH):   {bch_address}")
print("-" * 20)

# Initialize the Wallet with a WIF private key
wallet_from_wif = Wallet(SAMPLE_KEY_WIF)
eth_from_wif = wallet_from_wif.get_address("ethereum")
print(f"Wallet initialized from WIF key.")
print(f"Ethereum Address from WIF: {eth_from_wif}")
print("-" * 20)

# Generate a completely new wallet
new_wallet = Wallet.generate()
print("Generated a new wallet:")
print(f"  New Private Key (WIF): {new_wallet.private_key.to_wif()}")
print(f"  New ETH Address:       {new_wallet.get_address('ethereum')}")


# --- 2. HD Wallet Examples (BIP39 & BIP32) ---

print("\n--- 2. HD Wallet Examples ---")

# Generate a new 24-word mnemonic phrase
mnemonic = generate_mnemonic(24)
print(f"Generated Mnemonic: {mnemonic}")

# Check if the mnemonic is valid
is_valid = validate_mnemonic(mnemonic)
print(f"Is mnemonic valid? {is_valid}")

# Create an HDWallet from the mnemonic
hd_wallet = HDWallet.from_mnemonic(mnemonic, passphrase="my_secure_password_123")

# Get the master extended private key (xprv)
xprv = hd_wallet.master_node.serialize_private()
print(f"Master Extended Private Key (xprv): {xprv}")

# Derive the first Ethereum account using a standard BIP44 path
eth_path = "m/44'/60'/0'/0/0"
eth_node = hd_wallet.derive_from_path(eth_path)

# Use the derived node's private key to create a standard Wallet object
derived_eth_wallet = Wallet(eth_node.private_key)
derived_eth_address = derived_eth_wallet.get_address("ethereum")
print(f"Derived ETH Address (from path {eth_path}): {derived_eth_address}")


# --- 3. Low-Level Key Management Examples ---

print("\n--- 3. Low-Level Key Examples ---")

# Create a PrivateKey object directly from its integer representation
pk_integer = 123456789123456789123456789123456789123456789
my_private_key = PrivateKey(pk_integer)
print(f"Created PrivateKey from integer: {my_private_key.int}")
print(f"  - As Hex: {my_private_key.hex}")
print(f"  - As WIF: {my_private_key.to_wif()}")

# Get the corresponding public key
my_public_key = my_private_key.get_public_key(compressed=True)
print(f"Derived Public Key (Compressed): {my_public_key.hex}")

# Generate an address directly from the PublicKey object
#
# vvv THIS IS THE CORRECTED LINE vvv
# The keyword argument must be 'network', not 'coin'.
ltc_addr_from_pubkey = my_public_key.get_address(
    network="litecoin", address_type="p2pkh"
)
print(f"Litecoin Address from PublicKey: {ltc_addr_from_pubkey}")


# --- 4. Standalone Utility Function Examples ---

print("\n--- 4. Standalone Utility Examples ---")

# Convert a known mnemonic to its seed
known_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
seed_bytes = mnemonic_to_seed(known_mnemonic)
print(f"Seed from 'abandon...' mnemonic: {seed_bytes.hex()}")

# Convert a WIF key to its components
private_key_bytes, is_compressed, network_name = wif_to_private_key(SAMPLE_KEY_WIF)
print(f"Decoded WIF {SAMPLE_KEY_WIF}:")
print(f"  - Private Key (bytes): {private_key_bytes.hex()}")
print(f"  - Is Compressed:       {is_compressed}")
print(f"  - Network:             {network_name}")
