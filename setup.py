#!/usr/bin/env python3
"""
Setup script for LibCrypto - Cryptocurrency Wallet Library

This setup.py compiles C extensions for cryptographic operations.
"""

import os
import sys
from pathlib import Path
from setuptools import setup, find_packages, Extension

# Ensure we're in the correct directory
SCRIPT_DIR = Path(__file__).parent.absolute()
os.chdir(SCRIPT_DIR)

# Read version from src/libcrypto/__init__.py
def get_version():
    """Extract version from __init__.py"""
    version_file = Path("src/libcrypto/__init__.py")
    if version_file.exists():
        with open(version_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith('__version__'):
                    # Extract version string
                    return line.split('=')[1].strip().strip('"\'')
    return "1.0.0"

# Read long description from README
def get_long_description():
    """Read README.md for long description"""
    readme_path = Path("README.md")
    if readme_path.exists():
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "LibCrypto - Comprehensive cryptocurrency wallet library"

# Define core directory
core_dir = Path("src/libcrypto/Core")

# Common compilation flags
common_flags = [
    '-DHAVE_STDINT_H',
    '-DHAVE_POSIX_MEMALIGN', 
    '-DPYCRYPTO_LITTLE_ENDIAN',
    '-DHAVE_X86INTRIN_H',
    '-DUSE_SSE2',
    '-DHAVE_UINT128',
    '-DSTATIC=static'
]

# Platform-specific flags
if sys.platform == 'win32':
    compile_args = ['/O2'] + [f'/D{flag[2:]}' if flag.startswith('-D') else flag for flag in common_flags]
    link_args = []
else:
    compile_args = ['-O3', '-Wall', '-Wno-unused-const-variable', '-msse2', '-maes'] + common_flags
    link_args = []

# Define C extensions
extensions = [
    # Hash extensions
    Extension(
        'libcrypto.Hash._SHA256',
        sources=[str(core_dir / 'SHA256.c')],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args
    ),
    Extension(
        'libcrypto.Hash._SHA512',
        sources=[str(core_dir / 'SHA512.c')],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args
    ),
    Extension(
        'libcrypto.Hash._SHA1',
        sources=[str(core_dir / 'SHA1.c')],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args
    ),
    Extension(
        'libcrypto.Hash._SHA224',
        sources=[str(core_dir / 'SHA224.c')],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args
    ),
    Extension(
        'libcrypto.Hash._SHA384',
        sources=[str(core_dir / 'SHA384.c')],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args
    ),
    Extension(
        'libcrypto.Hash._RIPEMD160',
        sources=[str(core_dir / 'RIPEMD160.c')],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args
    ),
    Extension(
        'libcrypto.Hash._MD5',
        sources=[str(core_dir / 'MD5.c')],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args
    ),
    Extension(
        'libcrypto.Hash._MD4',
        sources=[str(core_dir / 'MD4.c')],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args
    ),
    Extension(
        'libcrypto.Hash._MD2',
        sources=[str(core_dir / 'MD2.c')],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args
    ),
    Extension(
        'libcrypto.Hash._keccak',
        sources=[str(core_dir / 'keccak.c')],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args
    ),
    Extension(
        'libcrypto.Hash._BLAKE2s',
        sources=[str(core_dir / 'blake2s.c')],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args
    ),
    Extension(
        'libcrypto.Hash._BLAKE2b',
        sources=[str(core_dir / 'blake2b.c')],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args
    ),
    # Extension(
    #     'libcrypto.Hash._poly1305',
    #     sources=[str(core_dir / 'poly1305.c')],
    #     include_dirs=[str(core_dir)],
    #     extra_compile_args=compile_args,
    #     extra_link_args=link_args
    # ),
    # Cipher extensions
    Extension(
        'libcrypto.Cipher._raw_aes',
        sources=[str(core_dir / 'AES.c')],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args
    ),
    Extension(
        'libcrypto.Cipher._Salsa20',
        sources=[str(core_dir / 'Salsa20.c')],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args
    ),
    # Protocol extensions
    Extension(
        'libcrypto.Protocol._scrypt',
        sources=[str(core_dir / 'scrypt.c')],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args
    ),
    # Note: AESNI disabled due to compilation issues - can be re-enabled with proper CPU detection
    # Extension(
    #     'libcrypto.Cipher._raw_aesni',
    #     sources=[str(core_dir / 'AESNI.c')],
    #     include_dirs=[str(core_dir)],
    #     extra_compile_args=compile_args,
    #     extra_link_args=link_args
    # ),
    # Utility extensions
    Extension(
        'libcrypto.Util._strxor',
        sources=[str(core_dir / 'strxor.c')],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args
    ),
]

# Main setup configuration
setup(
    name="libcrypto",
    version=get_version(),
    description="Comprehensive cryptocurrency wallet library with BIP39/BIP32 support and optimized C extensions",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="LibCrypto Team",
    author_email="info@libcrypto.dev",
    url="https://github.com/libcrypto-dev/libcrypto",
    project_urls={
        "Documentation": "https://libcrypto.readthedocs.io",
        "Source": "https://github.com/libcrypto-dev/libcrypto",
        "Tracker": "https://github.com/libcrypto-dev/libcrypto/issues",
        "PyPI": "https://pypi.org/project/libcrypto/"
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={
        "libcrypto": [
            "py.typed",
            "*.md"
        ]
    },
    ext_modules=extensions,
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "isort>=5.10.0"
        ],
        "test": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0"
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Office/Business :: Financial",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
        "Typing :: Typed"
    ],
    keywords=[
        "cryptocurrency", "bitcoin", "ethereum", "wallet", "bip39", "bip32", "bip44",
        "mnemonic", "private-key", "public-key", "address", "hdwallet", "crypto",
        "blockchain", "litecoin", "dash", "dogecoin", "bitcoin-cash", "secp256k1"
    ],
    license="MIT",
    zip_safe=False,
    include_package_data=True
) 