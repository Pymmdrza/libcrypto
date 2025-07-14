"""
Setup script for libcrypto package.
"""

from setuptools import setup, find_packages
import os


def get_long_description():
    """Get the long description from README.md."""
    readme_path = os.path.join(os.path.dirname(__file__), "README.md")
    if os.path.exists(readme_path):
        with open(readme_path, encoding="utf-8") as f:
            return f.read()
    return ""


setup(
    name="libcrypto",
    version="1.0.5",
    description="Comprehensive cryptocurrency wallet library with BIP39/BIP32 support using only pycryptodome",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="Mmdrza",
    author_email="pymmdrza@gmail.com",
    url="https://github.com/pymmdrza/libcrypto",
    project_urls={
        "Homepage": "https://github.com/pymmdrza/libcrypto",
        "Documentation": "https://libcrypto.readthedocs.io",
        "Repository": "https://github.com/pymmdrza/libcrypto.git",
        "Issues": "https://github.com/pymmdrza/libcrypto/issues",
        "PyPI": "https://pypi.org/project/libcrypto/",
    },
    license="MIT",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "pycryptodome>=3.23.0",
        "rich>=14.0.0",
        "wheel>=0.45.1",
        "setuptools>=80.9.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "isort>=5.10.0",
            "mypy>=1.0.0",
        ],
        "test": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
        ],
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
        "Typing :: Typed",
    ],
    keywords=[
        "cryptocurrency", "bitcoin", "ethereum", "wallet", "bip39", "bip32", "bip44",
        "mnemonic", "private-key", "public-key", "address", "hdwallet", "crypto",
        "blockchain", "litecoin", "dash", "dogecoin", "bitcoin-cash", "secp256k1",
        "pycryptodome", "cryptography",
    ],
    zip_safe=False,
    entry_points={
        "console_scripts": [
            # Add any command-line tools here if needed
        ],
    },
)
