LibCrypto Project Plan
======================

Overview
--------
LibCrypto is a Python package that exposes a high-level wallet API, cryptographic utilities, and a CLI for working with secp256k1-based cryptocurrencies. The source lives under `src/libcrypto`, which is distributed as a typed package via `pyproject.toml`. Runtime dependencies include `pycryptodome`, `ecdsa`, `typer`, and `rich`.

Architecture
------------
- `addresses.py`: Implements address generation for Bitcoin-style and account-based networks, including Bech32 support.
- `keys.py`: Defines `PrivateKey` and `PublicKey` wrappers with WIF conversion and caching.
- `bip32.py`: Provides hierarchical deterministic wallet support (`HDNode`, `HDWallet`).
- `mnemonic.py`: Supplies BIP39 helpers for entropy conversion, validation, and seed derivation.
- `secp256k1.py`: Wraps `ecdsa` for key derivation, compression, and point extraction.
- `wallet.py`: Supplies a user-friendly `Wallet` class that orchestrates private keys and address generation.
- `cli.py`: Exposes CLI commands through Typer for wallet operations, mnemonics, and package info.

Supporting modules (`constants.py`, `formats.py`, `hash.py`) provide shared data, format conversions, and cryptographic primitives.

Coding Standards
----------------
- Follow PEP8 with Black formatting.
- Type hints are encouraged; package ships `py.typed` for static typing consumers.
- Input validation should raise descriptive custom errors (`KeyError`, `AddressError`, etc.).
- Keep modules under 500 lines; split responsibilities along feature boundaries.

Testing & Tooling Strategy
--------------------------
- Use `pytest` for unit tests located in `tests/`, mirroring package structure where practical.
- Provide fixtures that prepare deterministic keys (e.g., private key `0x1`) for reproducible assertions.
- Verify expected flows, edge cases, and failure scenarios for key primitives (keys, addresses, BIP32, mnemonics, wallet facade).
- Automate testing in CI before building wheels or publishing (see GitHub workflows under `.github/workflows/`).

Documentation & Maintenance
---------------------------
- Update `README.md` when adding CLI options or altering installation instructions.
- Record development tasks in `TASK.md` with date stamps; mark completion promptly.
- Surface any discovered issues or debt under a “Discovered During Work” section in `TASK.md`.
