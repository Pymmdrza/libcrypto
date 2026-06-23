"""Command line interface for libcrypto using only the Python standard library."""
from __future__ import annotations

import argparse
import sys
from typing import Iterable, List

from . import __version__
from .mnemonic import generate_mnemonic, validate_mnemonic
from .wallet import COIN_CONFIG, Wallet

_DEFAULT_COINS = [
    "bitcoin",
    "ethereum",
    "tron",
    "ripple",
    "litecoin",
    "dogecoin",
    "dash",
    "bitcoin_cash",
]


def _print_key_values(title: str, rows: Iterable[tuple[str, str]]) -> None:
    print(title)
    print("-" * len(title))
    for key, value in rows:
        print(f"{key}: {value}")


def _command_info(_: argparse.Namespace) -> int:
    _print_key_values(
        "libcrypto",
        [
            ("Version", __version__),
            ("Description", "A professional library for cryptography and cryptocurrencies in Python."),
            ("Repository", "https://github.com/Pymmdrza/libcrypto"),
        ],
    )
    return 0


def _command_generate(args: argparse.Namespace) -> int:
    wallet = Wallet(args.private_key) if args.private_key else Wallet.generate()

    _print_key_values(
        "Wallet Keys",
        [
            ("Private Key (Hex)", wallet.private_key.hex),
            ("Private Key (WIF)", wallet.private_key.to_wif()),
            ("Public Key (Compressed)", wallet._public_key_compressed.hex),
            ("Public Key (Uncompressed)", wallet._public_key_uncompressed.hex),
        ],
    )

    print("\nGenerated Addresses")
    print("-------------------")
    for coin in args.coins:
        coin = coin.lower()
        if coin not in COIN_CONFIG:
            print(f"{coin}: unsupported coin")
            continue
        for addr_type, address in wallet.get_all_addresses(coin).items():
            print(f"{coin} [{addr_type}]: {address}")
    return 0


def _command_mnemonic_generate(args: argparse.Namespace) -> int:
    print(generate_mnemonic(args.words))
    return 0


def _command_mnemonic_validate(args: argparse.Namespace) -> int:
    is_valid = validate_mnemonic(args.phrase)
    print("valid" if is_valid else "invalid")
    return 0 if is_valid else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="libcrypto",
        description="Manage crypto keys, addresses, and BIP39 mnemonics.",
    )
    parser.add_argument("--version", "-v", action="store_true", help="Show version and exit.")

    subparsers = parser.add_subparsers(dest="command")

    info_parser = subparsers.add_parser("info", help="Display package information.")
    info_parser.set_defaults(func=_command_info)

    generate_parser = subparsers.add_parser("generate", help="Generate wallet addresses.")
    generate_parser.add_argument(
        "--private-key",
        "-p",
        help="Generate addresses from an existing WIF or 64-character hex private key.",
    )
    generate_parser.add_argument(
        "--coin",
        "-c",
        dest="coins",
        action="append",
        default=None,
        help="Coin to generate. Can be used multiple times.",
    )
    generate_parser.set_defaults(func=_command_generate)

    mnemonic_parser = subparsers.add_parser("mnemonic", help="BIP39 mnemonic tools.")
    mnemonic_subparsers = mnemonic_parser.add_subparsers(dest="mnemonic_command")

    mnemonic_generate = mnemonic_subparsers.add_parser("generate", help="Generate a mnemonic phrase.")
    mnemonic_generate.add_argument("--words", "-w", type=int, default=12, help="Word count: 12, 15, 18, 21, or 24.")
    mnemonic_generate.set_defaults(func=_command_mnemonic_generate)

    mnemonic_validate = mnemonic_subparsers.add_parser("validate", help="Validate a mnemonic phrase.")
    mnemonic_validate.add_argument("phrase", help="Mnemonic phrase enclosed in quotes.")
    mnemonic_validate.set_defaults(func=_command_mnemonic_validate)

    return parser


def app(argv: List[str] | None = None) -> int:
    """Console-script entry point."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"libcrypto version: {__version__}")
        return 0

    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    if getattr(args, "coins", None) is None:
        args.coins = list(_DEFAULT_COINS)

    try:
        return int(args.func(args))
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(app())
