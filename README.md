[![Python Version](https://img.shields.io/pypi/v/libcrypto?color=blue&logo=python)](https://pypi.org/project/libcrypto/)
[![License](https://img.shields.io/pypi/l/libcrypto)](LICENSE)

# LibCrypto

A professional library for Cryptography and Cryptocurrencies in Python.

This library provides a comprehensive suite of tools for developers working with cryptocurrencies, focusing on key management and address generation with a clean, high-level API.

## Key Features

- **High-Level Wallet API**: A simple `Wallet` class to manage keys and addresses.
- **Multi-Currency Support**: Correctly generate addresses for numerous secp256k1-based cryptocurrencies, including:
  - Bitcoin (BTC) - Legacy, SegWit (P2SH & Native)
  - Ethereum (ETH)
  - Tron (TRX)
  - Ripple (XRP)
  - Bitcoin Cash (BCH) - CashAddr format
  - Litecoin (LTC)
  - Dash (DASH)
  - Dogecoin (DOGE)
- **Hierarchical Deterministic (HD) Wallets**: Full BIP32 support for generating wallets from a master seed.
- **BIP39 Mnemonic Support**: Generate, validate, and derive seeds from mnemonic phrases.
- **Key & Format Conversions**: Easily convert between WIF, Hex, and Bytes for private and public keys.
- **Powerful Command-Line Interface**: Perform common wallet operations directly from your terminal.

## Installation

Install the library using pip:
```bash
pip install libcrypto
```

#### Install On Debian/Ubuntu
```bash
sudo apt-get install build-essential python3-dev
pip3 install libcrypto
```

#### Install On Fedora
```bash
sudo yum install gcc gmp python-devel
pip3 install libcrypto
```

#### Windows Installation
> [!NOTE]
> **Once only**
>  Download [Build Tools for Visual Studio 2019](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2019).
   In the installer, select the `C++ build tools`, the `Windows 10 SDK`, and the latest version of `MSVC v142 x64/x86 build tools`.




### Dependencies

The library uses:
- **Python stdlib**: `hashlib`, `hmac`, `os.urandom` for hashing and random number generation
- **Pure Python**: Custom secp256k1 elliptic curve implementation
- 
### Verification

Verify the library works without external crypto dependencies:
```bash
python verify_no_deps.py
```

## Quick Start (Library Usage)

```python
from libcrypto import Wallet

key = "Your private key here (hex)"
# Initialize the Wallet with the private key
# Replace "Your private key here (hex)" with your actual private key in hexadecimal format
wallet = Wallet(key)
# Generate P2PKH, P2SH-P2WPKH, P2WPKH addresses for Bitcoin
p2pkh = wallet.get_address(coin="bitcoin", address_type="p2pkh")
p2wsh = wallet.get_address(coin="bitcoin", address_type="p2sh-p2wpkh")
p2wpkh = wallet.get_address(coin="bitcoin", address_type="p2wpkh")
# Generate ethereum Address
ethereum_address = wallet.get_address(coin="ethereum")
# Generate Dash Address
dash = wallet.get_address(coin="dash")
# Generate Dogecoin Address
dogecoin_address = wallet.get_address(coin="dogecoin")
# Generate Tron Address
tron_address = wallet.get_address(coin="tron")
# Generate Ripple Address
ripple_address = wallet.get_address(coin="ripple")
# Generate Litecoin Address
litecoin_address = wallet.get_address(coin="litecoin")
# Generate Litecoin Address with specific address types
litecoin_address_p2pkh = wallet.get_address(coin="litecoin", address_type="p2pkh")
litecoin_address_p2wsh = wallet.get_address(coin="litecoin", address_type="p2sh-p2wpkh")
litecoin_address_p2wpkh = wallet.get_address(coin="litecoin", address_type="p2wpkh")
```

The library is designed to be straightforward. Here is a basic example of generating addresses from an existing private key.

```python
from libcrypto import Wallet

# Initialize a wallet from a WIF private key
wif_key = "L4ZQks37JHUadEqaj2nGB1eaZFcsRZwZGQ7WVYuQiztzg4pqopU6"  # Example WIF key
wallet = Wallet(wif_key)

# Generate addresses for different coins
eth_address = wallet.get_address('ethereum')
btc_address = wallet.get_address('bitcoin', address_type='p2wpkh') # Native SegWit
bch_address = wallet.get_address('bitcoin_cash')

print(f"Ethereum Address: {eth_address}")
print(f"Bitcoin (SegWit) Address: {btc_address}")
print(f"Bitcoin Cash Address: {bch_address}")
```

![CLI](https://raw.githubusercontent.com/Pymmdrza/libcrypto/refs/heads/main/.github/libcrypto_generate.png 'Libcrypto')


## Quick Start (Command-Line Interface)

```bash
# version
libcrypto -v
``` 

Package Information:
```bash
libcrypto info
```

### Wallet & Address Generation
- Generate a Wallet:
    This is the main command for generating new wallets or deriving addresses from existing keys.
```bash
libcrypto generate [OPTIONS]
```

Options:

-  `-p`, `--private-key` TEXT: Derive addresses from an existing private key (WIF or Hex format). If omitted, a new random wallet is generated.
-  `-c`, `--coin` TEXT: Specify a coin to generate addresses for. This option can be used multiple times. Defaults to bitcoin and ethereum.


1. Generate a new wallet for Bitcoin and Litecoin:
```bash
libcrypto generate -c bitcoin -c litecoin
```

2. Generate a wallet from an existing private key:
```bash
libcrypto generate -p <your-private-key>
```

3. Derive addresses for a specific set of coins from a hex key:
```bash
libcrypto generate -p <your-hex-key> -c bitcoin -c ethereum -c dash -c tron
```

### Mnemonic Management

The mnemonic subcommand is used for all BIP39 mnemonic phrase operations.
Generate a Mnemonic Phrase

Creates a new, cryptographically secure BIP39 mnemonic phrase.

```bash
libcrypto mnemonic generate [OPTIONS]
```

Options:

   - `-w`, `--words` INTEGER: The number of words in the mnemonic. Can be 12, 15, 18, 21, or 24. [Default: 12]

Example:
```bash
libcrypto mnemonic generate --words 24
```

### Validate a Mnemonic Phrase

Checks if a given BIP39 mnemonic phrase is valid according to the checksum rules.

```bash
libcrypto mnemonic validate "PHRASE"
```

Arguments:

- `PHRASE`: The full mnemonic phrase, enclosed in double quotes. [Required]

Example:
```bash
libcrypto mnemonic validate "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

## Donate

If you find this library useful, consider supporting its development:

- **Bitcoin (BTC)**: `1MMDRZAcM6dzmdMUSV8pDdAPDFpwzve9Fc`

## Contact

For support or inquiries, please contact us at [pymmdrza@gmail.com](mailto:pymmdrza@gmail.com).


