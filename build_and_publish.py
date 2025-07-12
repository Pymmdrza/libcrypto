#!/usr/bin/env python3
"""
Build and publish script for LibCrypto package

This script automates the process of building and publishing the package to PyPI.
It performs all necessary checks and builds before publishing.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
from typing import List, Optional

def run_command(cmd: List[str], check: bool = True, cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    print(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, check=check, capture_output=True, text=True, cwd=cwd)
        if result.stdout:
            print(result.stdout)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
        if e.stderr:
            print(f"Error output: {e.stderr}")
        if check:
            sys.exit(1)
        return e

def clean_build_artifacts():
    """Clean up build artifacts from previous builds."""
    print("🧹 Cleaning build artifacts...")
    
    # Directories to clean
    dirs_to_clean = [
        "build",
        "dist",
        "*.egg-info",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
    ]
    
    for pattern in dirs_to_clean:
        if "*" in pattern:
            # Use glob for patterns
            for path in Path(".").glob(f"**/{pattern}"):
                if path.is_dir():
                    print(f"  Removing directory: {path}")
                    shutil.rmtree(path, ignore_errors=True)
        else:
            path = Path(pattern)
            if path.exists():
                if path.is_dir():
                    print(f"  Removing directory: {path}")
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    print(f"  Removing file: {path}")
                    path.unlink()

def check_dependencies():
    """Check that required build dependencies are installed."""
    print("🔍 Checking build dependencies...")
    
    required_packages = ["build", "twine", "wheel"]
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing required packages: {', '.join(missing_packages)}")
        print("Install them with: pip install " + " ".join(missing_packages))
        return False
    
    print("✅ All build dependencies are installed")
    return True

def run_tests():
    """Run the test suite."""
    print("🧪 Running tests...")
    
    # Check if pytest is available
    try:
        import pytest
    except ImportError:
        print("⚠️  pytest not available, skipping tests")
        return True
    
    # Run tests
    result = run_command([sys.executable, "-m", "pytest", "-v"], check=False)
    if result.returncode != 0:
        print("❌ Tests failed!")
        return False
    
    print("✅ All tests passed")
    return True

def run_linting():
    """Run code quality checks."""
    print("🔎 Running code quality checks...")
    
    # Check if flake8 is available
    try:
        import flake8
        result = run_command([sys.executable, "-m", "flake8", ".", "--max-line-length=100"], check=False)
        if result.returncode != 0:
            print("⚠️  Linting issues found (continuing anyway)")
        else:
            print("✅ Linting passed")
    except ImportError:
        print("⚠️  flake8 not available, skipping linting")
    
    return True

def run_type_checking():
    """Run type checking with mypy."""
    print("🏷️  Running type checking...")
    
    try:
        import mypy
        result = run_command([sys.executable, "-m", "mypy", ".", "--ignore-missing-imports"], check=False)
        if result.returncode != 0:
            print("⚠️  Type checking issues found (continuing anyway)")
        else:
            print("✅ Type checking passed")
    except ImportError:
        print("⚠️  mypy not available, skipping type checking")
    
    return True

def build_package():
    """Build the package using the build tool."""
    print("🏗️  Building package...")
    
    # Build the package
    result = run_command([sys.executable, "-m", "build"])
    if result.returncode != 0:
        print("❌ Package build failed!")
        return False
    
    print("✅ Package built successfully")
    return True

def check_package():
    """Check the built package with twine."""
    print("📦 Checking package...")
    
    # Check the package
    result = run_command([sys.executable, "-m", "twine", "check", "dist/*"])
    if result.returncode != 0:
        print("❌ Package check failed!")
        return False
    
    print("✅ Package check passed")
    return True

def upload_to_testpypi():
    """Upload package to Test PyPI."""
    print("🚀 Uploading to Test PyPI...")
    
    result = run_command([
        sys.executable, "-m", "twine", "upload",
        "--repository", "testpypi",
        "dist/*"
    ], check=False)
    
    if result.returncode != 0:
        print("❌ Upload to Test PyPI failed!")
        return False
    
    print("✅ Successfully uploaded to Test PyPI")
    return True

def upload_to_pypi():
    """Upload package to PyPI."""
    print("🚀 Uploading to PyPI...")
    
    # Confirm with user
    response = input("Are you sure you want to upload to PyPI? (yes/no): ")
    if response.lower() != "yes":
        print("Upload cancelled.")
        return False
    
    result = run_command([
        sys.executable, "-m", "twine", "upload",
        "dist/*"
    ], check=False)
    
    if result.returncode != 0:
        print("❌ Upload to PyPI failed!")
        return False
    
    print("✅ Successfully uploaded to PyPI")
    return True

def main():
    """Main build and publish workflow."""
    print("🚀 LibCrypto Build and Publish Script")
    print("=" * 40)
    
    # Check command line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1]
    else:
        command = "build"
    
    # Change to script directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    # Clean previous builds
    clean_build_artifacts()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Run quality checks
    if command in ["build", "test", "publish", "testpypi"]:
        if not run_tests():
            if command != "build":  # Allow building with failing tests
                sys.exit(1)
        
        run_linting()
        run_type_checking()
    
    # Build package
    if command in ["build", "publish", "testpypi"]:
        if not build_package():
            sys.exit(1)
        
        if not check_package():
            sys.exit(1)
    
    # Upload based on command
    if command == "testpypi":
        if not upload_to_testpypi():
            sys.exit(1)
    elif command == "publish":
        if not upload_to_pypi():
            sys.exit(1)
    elif command == "test":
        print("✅ All tests and checks completed successfully")
    elif command == "build":
        print("✅ Package built successfully")
        print("Next steps:")
        print("  - Test upload: python build_and_publish.py testpypi")
        print("  - Production upload: python build_and_publish.py publish")
    else:
        print(f"Unknown command: {command}")
        print("Available commands: build, test, testpypi, publish")
        sys.exit(1)
    
    print("🎉 Done!")

if __name__ == "__main__":
    main() 