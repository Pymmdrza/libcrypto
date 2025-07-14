# LibCrypto - Cryptocurrency Wallet Library

A comprehensive, self-contained Python cryptocurrency wallet library that provides all necessary tools for generating and managing cryptocurrency wallet keys and addresses **without any external dependencies**.

## 🚀 Features

### Core Functionality
- **BIP39 Mnemonic Phrases**: Generate and validate secure mnemonic phrases (12, 15, 18, 21, 24 words)
- **BIP32 HD Wallets**: Hierarchical deterministic wallet support with full BIP44 compliance
- **Multi-Currency Support**: Generate addresses for 13+ cryptocurrencies
- **Key Format Conversions**: Convert between hex, WIF, bytes, decimal, and mnemonic formats
- **Zero Dependencies**: Uses only Python standard library and included C extensions

### Supported Cryptocurrencies
- **Bitcoin (BTC)** - P2PKH, P2SH, P2WPKH, P2WSH (SegWit)
- **Ethereum (ETH)** - Native addresses with EIP-55 checksum
- **Litecoin (LTC)** - All Bitcoin-compatible formats
- **Bitcoin Cash (BCH)** - Legacy and CashAddr formats
- **Bitcoin Gold (BTG)** - All standard formats
- **Dogecoin (DOGE)** - P2PKH and P2SH
- **Dash** - P2PKH and P2SH
- **Digibyte (DGB)** - All standard formats
- **Zcash (ZEC)** - T-addresses
- **Tron (TRX)** - Native TRX addresses
- **Solana (SOL)** - Base58 encoded addresses
- **Avalanche (AVAX)** - C-Chain addresses
- **TON** - Native TON addresses
- **Ripple (XRP)** - Classic addresses

### Address Formats
- **P2PKH**: Pay to Public Key Hash (1...)
- **P2SH**: Pay to Script Hash (3...)
- **P2WPKH**: Pay to Witness Public Key Hash (bc1...)
- **P2WSH**: Pay to Witness Script Hash (bc1...)
- **Ethereum**: Keccak256-based addresses (0x...)

## 📦 Installation

```bash
# Clone the repository
git clone <repository-url>
cd libcrypto

# Install in development mode
pip install -e .
```

## 🔧 Quick Start

### Generate a New Mnemonic and Wallet

```python
import mnemonic
from wallet import HDWallet, PrivateKey, AddressGenerator

# Generate a new 12-word mnemonic
new_mnemonic = mnemonic.generate_mnemonic(12)
print(f"Generated mnemonic: {new_mnemonic}")

# Create HD wallet from mnemonic
wallet = HDWallet.from_mnemonic(new_mnemonic)

# Get Bitcoin address (BIP44 path: m/44'/0'/0'/0/0)
btc_key = wallet.derive_address_key(coin_type=0, address_index=0)
btc_address = AddressGenerator.from_public_key(
    btc_key.public_key, 'p2pkh', 'bitcoin'
)
print(f"Bitcoin address: {btc_address}")

# Get Ethereum address (BIP44 path: m/44'/60'/0'/0/0)
eth_key = wallet.derive_address_key(coin_type=60, address_index=0)
eth_address = AddressGenerator.from_public_key(
    eth_key.public_key, 'ethereum', 'ethereum'
)
print(f"Ethereum address: {eth_address}")
```

### Import Existing Mnemonic

```python
import mnemonic
from wallet import HDWallet

# Import existing mnemonic
existing_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Validate mnemonic
if mnemonic.validate_mnemonic(existing_mnemonic):
    print("✅ Mnemonic is valid")
    
    # Create wallet
    wallet = HDWallet.from_mnemonic(existing_mnemonic)
    
    # Get master keys
    print(f"Master private key: {wallet.get_master_private_key()}")
    print(f"Master public key: {wallet.get_master_public_key()}")
else:
    print("❌ Invalid mnemonic")
```

### Private Key Operations

```python
from wallet import PrivateKey

# Generate a new private key
private_key = PrivateKey.generate()

# Convert to different formats
print(f"Hex: {private_key.hex}")
print(f"WIF: {private_key.to_wif()}")
print(f"Decimal: {private_key.decimal}")

# Get public key and address
public_key = private_key.get_public_key()
btc_address = public_key.get_address('p2pkh', 'bitcoin')
print(f"Bitcoin address: {btc_address}")

# Import from hex
hex_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
imported_key = PrivateKey.from_hex(hex_key)
print(f"Imported key WIF: {imported_key.to_wif()}")
```

### Multiple Address Generation

```python
from wallet import HDWallet, AddressGenerator

# Create wallet from mnemonic
mnemonic_phrase = "your twelve word mnemonic phrase goes here example test words"
wallet = HDWallet.from_mnemonic(mnemonic_phrase)

# Generate first 5 Bitcoin addresses
for i in range(5):
    key = wallet.derive_address_key(coin_type=0, address_index=i)
    
    # Generate different Bitcoin address formats
    p2pkh = AddressGenerator.from_public_key(key.public_key, 'p2pkh', 'bitcoin')
    p2wpkh = AddressGenerator.from_public_key(key.public_key, 'p2wpkh', 'bitcoin')
    
    print(f"Address {i}:")
    print(f"  P2PKH:  {p2pkh}")
    print(f"  P2WPKH: {p2wpkh}")
```

### Multi-Currency Wallet

```python
from wallet import HDWallet, AddressGenerator
from Util.constants import BIP44_COIN_TYPES

# Create wallet
wallet = HDWallet.from_mnemonic("your mnemonic here")

# Generate addresses for different cryptocurrencies
currencies = ['bitcoin', 'ethereum', 'litecoin', 'dogecoin']

for currency in currencies:
    coin_type = BIP44_COIN_TYPES[currency]
    key = wallet.derive_address_key(coin_type=coin_type, address_index=0)
    
    if currency == 'ethereum':
        address = AddressGenerator.from_public_key(key.public_key, 'ethereum', 'ethereum')
    else:
        address = AddressGenerator.from_public_key(key.public_key, 'p2pkh', currency)
    
    print(f"{currency.capitalize()}: {address}")
```

## API Overview

### Mnemonic Module (`mnemonic.py`)
- `generate_mnemonic(word_count)` - Generate new mnemonic
- `validate_mnemonic(mnemonic)` - Validate existing mnemonic
- `mnemonic_to_seed(mnemonic, passphrase)` - Convert to seed

### HD Wallet (`wallet.HDWallet`)
- `from_mnemonic(mnemonic, passphrase, network)` - Create from mnemonic
- `derive_account(coin_type, account)` - Derive account key
- `derive_address_key(coin_type, account, change, address_index)` - Derive address key

### Private Key (`wallet.PrivateKey`)
- `generate(network)` - Generate new key
- `from_hex(hex_str, network)` - Import from hex
- `from_wif(wif)` - Import from WIF
- `to_wif(compressed)` - Export to WIF
- `get_public_key(compressed)` - Get public key

### Public Key (`wallet.PublicKey`)
- `from_hex(hex_str, compressed)` - Import from hex
- `get_address(address_type, network)` - Generate address
- `to_compressed()` / `to_uncompressed()` - Format conversion

### Address Generator (`wallet.AddressGenerator`)
- `from_public_key(public_key, address_type, network)` - Generate address
- `generate_multiple_formats(public_key, network)` - All formats
- `validate_address(address, network)` - Validate address

## Security Features

- **Cryptographically Secure**: Uses `secrets` module for random number generation
- **Proper Entropy**: Validates entropy for mnemonic generation
- **Checksum Validation**: All mnemonics include BIP39 checksum verification
- **Constant-Time Operations**: Where possible, uses constant-time implementations
- **Zero External Dependencies**: Reduces attack surface by avoiding third-party libraries



## Advanced Usage

### Custom Derivation Paths

```python
from wallet import HDWallet

wallet = HDWallet.from_mnemonic("your mnemonic")

# Custom derivation path
custom_path = "m/44'/0'/0'/0/5"  # 6th address
custom_key = wallet.master_node.derive_path(custom_path)

# Account-level derivation for exchange integration
account_key = wallet.derive_account(coin_type=0, account=1)  # Second account
```

### Batch Address Generation

```python
from wallet import HDWallet, AddressGenerator

def generate_address_batch(mnemonic, coin_type, count=100):
    """Generate a batch of addresses efficiently."""
    wallet = HDWallet.from_mnemonic(mnemonic)
    addresses = []
    
    for i in range(count):
        key = wallet.derive_address_key(coin_type=coin_type, address_index=i)
        address = AddressGenerator.from_public_key(key.public_key, 'p2pkh', 'bitcoin')
        addresses.append({
            'index': i,
            'address': address,
            'private_key': key.private_key.hex(),
            'public_key': key.public_key.hex()
        })
    
    return addresses

# Generate first 100 Bitcoin addresses
btc_addresses = generate_address_batch("your mnemonic", coin_type=0, count=100)
```

## Performance

Typical performance on modern hardware:
- **Mnemonic generation**: < 100ms
- **Address generation**: < 50ms per address
- **Key derivation**: < 200ms for complex paths
- **Memory usage**: < 50MB for typical operations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Standards Compliance

- **BIP-39**: Mnemonic code for generating deterministic keys
- **BIP-32**: Hierarchical Deterministic (HD) Wallets
- **BIP-44**: Multi-Account Hierarchy for Deterministic Wallets
- **EIP-55**: Mixed-case checksum address encoding (Ethereum)
- **RFC-6979**: Deterministic Usage of DSA and ECDSA


---

**LibCrypto** - Professional Cryptocurrency Wallet Library with Zero Dependencies 

