import re
import sys
import os
from pathlib import Path

# --- Get package name from command-line arguments, with a default value ---
args = sys.argv[1:]
package_name = args[0] if args else "libcrypto"


def bump_version(version: str) -> str:
    """Bumps the version number according to a custom logic."""
    try:
        major, minor, patch = map(int, version.split('.'))
    except ValueError:
        print(f"Error: Invalid version format '{version}'. Expected 'major.minor.patch'.", file=sys.stderr)
        sys.exit(1)

    patch += 1
    if patch >= 10:
        patch = 0
        minor += 1
        if minor >= 10:
            minor = 0
            major += 1
    if minor == 0 and patch == 0:
        # This keeps your original logic: avoid 1.0.0 by bumping to 1.0.3
        patch = 3

    return f"{major}.{minor}.{patch}"


def get_init_path(package_name: str) -> Path:
    """Constructs the path to the __init__.py file."""
    # Assuming script runs from repo root
    current = Path(__file__).resolve().parent
    lib_src = current / "src" / package_name
    return lib_src / "__init__.py"


def get_version_from_init(init_path: Path) -> str:
    """Reads the version number from the __init__.py file."""
    try:
        content = init_path.read_text(encoding='utf-8')
    except FileNotFoundError:
        print(f"Error: __init__.py not found at '{init_path}'", file=sys.stderr)
        sys.exit(1)

    match = re.search(r"^__version__\s*=\s*['\"]([^'\"]*)['\"]", content, re.M)
    if match:
        return match.group(1)
    else:
        print("Error: Unable to find __version__ string in __init__.py", file=sys.stderr)
        sys.exit(1)


def update_file_version(file_path: Path, pattern: re.Pattern, new_line: str):
    """A generic function to update the version in a given file."""
    if not file_path.exists():
        print(f"Info: Skipping update for non-existent file: {file_path}", file=sys.stderr)
        return

    try:
        content = file_path.read_text(encoding='utf-8')

        # Check if the pattern exists before trying to substitute
        if not pattern.search(content):
            print(f"Warning: Version pattern not found in {file_path}. Skipping update.", file=sys.stderr)
            return

        updated = pattern.sub(new_line, content)
        file_path.write_text(updated, encoding='utf-8')

        print(f"Successfully updated version in: {file_path.name}", file=sys.stderr)

    except Exception as e:
        print(f"Error updating file {file_path}: {e}", file=sys.stderr)


# --- Main execution block ---
if __name__ == "__main__":
    # 1. Get the current version from the single source of truth (__init__.py)
    init_path = get_init_path(package_name)
    current_version = get_version_from_init(init_path)

    # 2. Calculate the new version
    new_version = bump_version(current_version)

    print(f"{'=' * 20}[ Bumping version from {current_version} to {new_version} ]{'=' * 20}", file=sys.stderr)

    # 3. Define patterns and replacements for each file
    # For __init__.py
    init_pattern = re.compile(r"^(__version__\s*=\s*['\"])([^'\"]*)(['\"])", re.M)
    init_new = f'__version__ = "{new_version}"'

    # For setup.py
    setup_pattern = re.compile(r"(version\s*=\s*['\"])([^'\"]*)(['\"])", re.M)
    setup_new = f'version="{new_version}"'

    # For pyproject.toml
    pyproject_pattern = re.compile(r"^(version\s*=\s*['\"])([^'\"]*)(['\"])", re.M)
    pyproject_new = f'version = "{new_version}"'

    # 4. Update all files
    update_file_version(init_path, init_pattern, init_new)
    setup_path = Path.cwd() / "setup.py"
    update_file_version(setup_path, setup_pattern, setup_new)
    pyproject_path = Path.cwd() / "pyproject.toml"
    update_file_version(pyproject_path, pyproject_pattern, pyproject_new)

    # 5. Write the new version to GitHub environment file for CI/CD
    github_env = os.environ.get("GITHUB_ENV")
    if github_env:
        try:
            with open(github_env, "a", encoding="utf-8") as env_file:
                env_file.write(f"NEW_VERSION={new_version}\n")
            print("Successfully wrote new version to GITHUB_ENV.", file=sys.stderr)
        except Exception as e:
            print(f"Warning: Could not write NEW_VERSION to GITHUB_ENV: {e}", file=sys.stderr)
    else:
        print("Info: GITHUB_ENV not found. Skipping environment file write.", file=sys.stderr)

    # 6. Print the new version to stdout for capture by CI (only the version)
    print(new_version)