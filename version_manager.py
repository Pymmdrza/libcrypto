#!/usr/bin/env python3
"""
Version management utility for libcrypto package.
Use this script to update version numbers across the entire project.
"""

import os
import re
import argparse
import sys
from pathlib import Path


def get_current_version():
    """Get the current version from _version.py"""
    version_file = Path(__file__).parent / "src" / "libcrypto" / "_version.py"

    if not version_file.exists():
        raise FileNotFoundError(f"Version file not found: {version_file}")

    with open(version_file, "r", encoding="utf-8") as f:
        content = f.read()

    # Extract version components
    major_match = re.search(r"VERSION_MAJOR\s*=\s*(\d+)", content)
    minor_match = re.search(r"VERSION_MINOR\s*=\s*(\d+)", content)
    patch_match = re.search(r"VERSION_PATCH\s*=\s*(\d+)", content)
    suffix_match = re.search(r'VERSION_SUFFIX\s*=\s*["\']([^"\']*)["\']', content)

    if not all([major_match, minor_match, patch_match, suffix_match]):
        raise ValueError("Could not parse version components from _version.py")

    major = int(major_match.group(1))
    minor = int(minor_match.group(1))
    patch = int(patch_match.group(1))
    suffix = suffix_match.group(1)

    return major, minor, patch, suffix


def update_version(major, minor, patch, suffix=""):
    """Update the version in _version.py"""
    version_file = Path(__file__).parent / "src" / "libcrypto" / "_version.py"

    with open(version_file, "r", encoding="utf-8") as f:
        content = f.read()

    # Update version components
    content = re.sub(r"VERSION_MAJOR\s*=\s*\d+", f"VERSION_MAJOR = {major}", content)
    content = re.sub(r"VERSION_MINOR\s*=\s*\d+", f"VERSION_MINOR = {minor}", content)
    content = re.sub(r"VERSION_PATCH\s*=\s*\d+", f"VERSION_PATCH = {patch}", content)
    content = re.sub(
        r'VERSION_SUFFIX\s*=\s*["\'][^"\']*["\']',
        f'VERSION_SUFFIX = "{suffix}"',
        content,
    )

    with open(version_file, "w", encoding="utf-8") as f:
        f.write(content)

    # Calculate version string
    if suffix:
        version_str = f"{major}.{minor}.{patch}{suffix}"
    else:
        version_str = f"{major}.{minor}.{patch}"

    return version_str


def validate_version_consistency():
    """Check if all files use the same version"""
    from src.libcrypto._version import __version__

    issues = []

    # Check if import works
    try:
        from src.libcrypto import __version__ as init_version

        if __version__ != init_version:
            issues.append(
                f"__init__.py version mismatch: {init_version} != {__version__}"
            )
    except ImportError as e:
        issues.append(f"Could not import version from __init__.py: {e}")

    return issues


def bump_version(component, suffix=""):
    """Bump version component (major, minor, patch)"""
    major, minor, patch, current_suffix = get_current_version()

    if component == "major":
        major += 1
        minor = 0
        patch = 0
    elif component == "minor":
        minor += 1
        patch = 0
    elif component == "patch":
        patch += 1
    else:
        raise ValueError(f"Invalid component: {component}")

    return update_version(major, minor, patch, suffix)


def main():
    """Main function for version management."""
    parser = argparse.ArgumentParser(
        description="libcrypto Version Management Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python version_manager.py --show                    Show current version
  python version_manager.py --set 1.2.3              Set specific version
  python version_manager.py --bump patch             Bump patch version
  python version_manager.py --bump minor             Bump minor version
  python version_manager.py --bump major             Bump major version
  python version_manager.py --set 2.0.0 --suffix rc1  Set version with suffix
  python version_manager.py --check                  Check version consistency
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--show", "-s", action="store_true", help="Show current version")
    group.add_argument("--set", type=str, help="Set specific version (e.g., 1.2.3)")
    group.add_argument(
        "--bump",
        "-b",
        choices=["major", "minor", "patch"],
        help="Bump version component",
    )
    group.add_argument(
        "--check",
        "-c",
        action="store_true",
        help="Check version consistency across files",
    )

    parser.add_argument(
        "--suffix", type=str, default="", help="Version suffix (e.g., a1, b1, rc1)"
    )

    args = parser.parse_args()

    try:
        if args.show:
            major, minor, patch, suffix = get_current_version()
            if suffix:
                version_str = f"{major}.{minor}.{patch}{suffix}"
            else:
                version_str = f"{major}.{minor}.{patch}"

            print(f"Current version: {version_str}")
            print(
                f"Components: major={major}, minor={minor}, patch={patch}, suffix='{suffix}'"
            )

        elif args.set:
            # Parse version string
            version_parts = args.set.split(".")
            if len(version_parts) != 3:
                raise ValueError(
                    "Version must be in format major.minor.patch (e.g., 1.2.3)"
                )

            try:
                major = int(version_parts[0])
                minor = int(version_parts[1])
                patch = int(version_parts[2])
            except ValueError:
                raise ValueError("Version components must be integers")

            new_version = update_version(major, minor, patch, args.suffix)
            print(f"Version updated to: {new_version}")

        elif args.bump:
            new_version = bump_version(args.bump, args.suffix)
            print(f"Version bumped to: {new_version}")

        elif args.check:
            issues = validate_version_consistency()
            if issues:
                print("Version consistency issues found:")
                for issue in issues:
                    print(f"  ❌ {issue}")
                sys.exit(1)
            else:
                major, minor, patch, suffix = get_current_version()
                if suffix:
                    version_str = f"{major}.{minor}.{patch}{suffix}"
                else:
                    version_str = f"{major}.{minor}.{patch}"
                print(f"✅ All versions are consistent: {version_str}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
