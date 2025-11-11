"""Pytest configuration for libcrypto tests."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"

if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))


@pytest.fixture(scope="session")
def deterministic_private_key_hex() -> str:
    """Return a canonical private key hex string for deterministic fixtures."""
    return "0000000000000000000000000000000000000000000000000000000000000001"
