#!/usr/bin/env python3
"""Update libcrypto's package version.

The public package version is read dynamically from src/libcrypto/_version.py
by setuptools through pyproject.toml.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[a-zA-Z0-9.+-]+)?$")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: python scripts/set_version.py <version>", file=sys.stderr)
        return 2

    version = argv[1].strip().lstrip("v")
    if not _VERSION_RE.match(version):
        print(f"Invalid version: {version}", file=sys.stderr)
        return 2

    root = Path(__file__).resolve().parents[1]
    version_file = root / "src" / "libcrypto" / "_version.py"
    text = version_file.read_text(encoding="utf-8")
    updated, count = re.subn(
        r'^(__version__\s*=\s*")[^"]+(")',
        rf'\g<1>{version}\2',
        text,
        flags=re.MULTILINE,
    )
    if count != 1:
        print("Unable to update __version__ in src/libcrypto/_version.py", file=sys.stderr)
        return 1

    version_file.write_text(updated, encoding="utf-8")
    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
