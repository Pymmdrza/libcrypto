#!/usr/bin/env python3
"""Local helper for incrementing the package patch version.

This script is intentionally self-contained and does not download or execute
remote code. It updates pyproject.toml, setup.py and src/libcrypto/_version.py.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VERSION_FILE = ROOT / "src" / "libcrypto" / "_version.py"


def _current_version() -> str:
    text = VERSION_FILE.read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    if not match:
        raise RuntimeError("Unable to find __version__ in src/libcrypto/_version.py")
    return match.group(1)


def _bump_patch(version: str) -> str:
    major, minor, patch = map(int, version.split(".")[:3])
    return f"{major}.{minor}.{patch + 1}"


def main() -> int:
    current = _current_version()
    new_version = _bump_patch(current)
    script = ROOT / "scripts" / "set_version.py"
    subprocess.check_call([sys.executable, str(script), new_version], cwd=ROOT)
    print(new_version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
