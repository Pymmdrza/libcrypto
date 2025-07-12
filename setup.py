from __future__ import print_function

try:
    from setuptools import Extension, Command, setup
    from setuptools.command.build_ext import build_ext
    from setuptools.command.build_py import build_py
except ImportError:
    from distutils.core import Extension, Command, setup
    from distutils.command.build_ext import build_ext
    from distutils.command.build_py import build_py

import re
import os
import sys
import shutil
import struct
import sysconfig
from pathlib import Path

sys.path.append(os.getcwd())

from compiler_opt import set_compiler_options

use_separate_namespace = os.path.isfile(".separate_namespace")

project_name = "libcrypto"
package_root = "src/libcrypto/Core"

if use_separate_namespace:
    project_name, other_project = other_project, project_name
    package_root, other_root = other_root, package_root


def read_file(filename):
    with open(filename, "r", encoding="utf-8") as f:
        return f.read()


def get_long_description():
    """Read README.md for long description"""
    readme_path = Path("README.md")
    if readme_path.exists():
        with open(readme_path, "r", encoding="utf-8") as f:
            return f.read()
    return "LibCrypto - Comprehensive cryptocurrency wallet library"


# Read version from src/libcrypto/__init__.py
def get_version():
    """Extract version from __init__.py"""
    version_file = Path("src/libcrypto/__init__.py")
    if version_file.exists():
        with open(version_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("__version__"):
                    # Extract version string
                    return line.split("=")[1].strip().strip("\"'")
    return "1.0.0"


# Read the long description from README.md
current_dir = os.path.dirname(os.path.abspath(__file__))
longdesc = get_long_description()


class PCTBuildExt(build_ext):

    # Avoid linking Python's dynamic library
    def get_libraries(self, ext):
        return []


class PCTBuildPy(build_py):
    def find_package_modules(self, package, package_dir, *args, **kwargs):
        modules = build_py.find_package_modules(
            self, package, package_dir, *args, **kwargs
        )

        # Exclude certain modules
        retval = []
        for item in modules:
            pkg, module = item[:2]
            retval.append(item)
        return retval


class TestCommand(Command):
    "Run self-test"

    # Long option name, short option name, description
    user_options = [
        ("skip-slow-tests", None, "Skip slow tests"),
        ("wycheproof-warnings", None, "Show warnings from wycheproof tests"),
        ("module=", "m", "Test a single module (e.g. Cipher, PublicKey)"),
    ]

    def initialize_options(self):
        self.build_dir = None
        self.skip_slow_tests = None
        self.wycheproof_warnings = None
        self.module = None

    def finalize_options(self):
        self.set_undefined_options("install", ("build_lib", "build_dir"))
        self.config = {
            "slow_tests": not self.skip_slow_tests,
            "wycheproof_warnings": self.wycheproof_warnings,
        }


def create_libcrypto_lib():
    assert os.path.isdir("src/libcrypto")

    try:
        shutil.rmtree("src/libcrypto")
    except OSError:
        pass
    for root_src, dirs, files in os.walk("src/libcrypto"):

        root_dst, nr_repl = re.subn("libcrypto", root_src)
        assert nr_repl == 1

        for dir_name in dirs:
            full_dir_name_dst = os.path.join(root_dst, dir_name)
            if not os.path.exists(full_dir_name_dst):
                os.makedirs(full_dir_name_dst)

        for file_name in files:
            full_file_name_src = os.path.join(root_src, file_name)
            full_file_name_dst = os.path.join(root_dst, file_name)

            print("Copying file %s to %s" % (full_file_name_src, full_file_name_dst))
            shutil.copy2(full_file_name_src, full_file_name_dst)

            if full_file_name_src.split(".")[-1] not in ("py", "pyi"):
                if full_file_name_src != "py.typed":
                    continue

            if sys.version_info[0] > 2:
                extra_param = {"encoding": "utf-8"}
            else:
                extra_param = {}
            with open(full_file_name_dst, "rt", **extra_param) as fd:
                content = fd.read().replace("Crypto.", "libcrypto.")
            os.remove(full_file_name_dst)
            with open(full_file_name_dst, "wt", **extra_param) as fd:
                fd.write(content)


# Parameters for setup
packages = [
    "libcrypto",
    "libcrypto.wallet",
    "libcrypto.Core",
    "libcrypto.Cipher",
    "libcrypto.Hash",
    "libcrypto.IO",
    "libcrypto.PublicKey",
    "libcrypto.Protocol",
    "libcrypto.Random",
    "libcrypto.Signature",
    "libcrypto.Util",
    "libcrypto.Math",
]
package_data = {
    "libcrypto": ["py.typed", "*.pyi"],
    "libcrypto.Cipher": ["*.pyi"],
    "libcrypto.Hash": ["*.pyi"],
    "libcrypto.Math": ["*.pyi"],
    "libcrypto.Protocol": ["*.pyi"],
    "libcrypto.PublicKey": ["*.pyi"],
    "libcrypto.Random": ["*.pyi"],
    "libcrypto.Signature": ["*.pyi"],
    "libcrypto.IO": ["*.pyi"],
    "libcrypto.Util": ["*.pyi"],
}
# Define core directory
core_dir = Path("src/libcrypto/Core")
# Common compilation flags
common_flags = [
    "-DHAVE_STDINT_H",
    "-DHAVE_POSIX_MEMALIGN",
    "-DPYCRYPTO_LITTLE_ENDIAN",
    "-DHAVE_X86INTRIN_H",
    "-DUSE_SSE2",
    "-DHAVE_UINT128",
    "-DSTATIC=static",
]
# Platform-specific flags
if sys.platform == "win32":
    compile_args = ["/O2"] + [
        f"/D{flag[2:]}" if flag.startswith("-D") else flag for flag in common_flags
    ]
    link_args = []
else:
    compile_args = [
        "-O3",
        "-Wall",
        "-Wno-unused-const-variable",
        "-msse2",
        "-maes",
    ] + common_flags
    link_args = []
# Ensure the Core directory exists
if not core_dir.exists():
    raise FileNotFoundError(f"Core directory not found: {core_dir}")
ext_modules = [
    # Hash functions
    Extension(
        "libcrypto.Hash._MD2",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "MD2.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Hash._MD4",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "MD4.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Hash._MD5",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "MD5.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Hash._SHA1",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "SHA1.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Hash._SHA256",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "SHA256.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Hash._SHA224",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "SHA224.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Hash._SHA384",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "SHA384.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Hash._SHA512",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "SHA512.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Hash._RIPEMD160",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "RIPEMD160.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Hash._keccak",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "keccak.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Hash._BLAKE2b",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "blake2b.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Hash._BLAKE2s",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "blake2s.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Hash._ghash_portable",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "ghash_portable.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Hash._ghash_clmul",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "ghash_clmul.c")],
        py_limited_api=True,
    ),
    # MACs
    Extension(
        "libcrypto.Hash._poly1305",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "poly1305.c")],
        py_limited_api=True,
    ),
    # Block encryption algorithms
    Extension(
        "libcrypto.Cipher._raw_aes",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "AES.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Cipher._raw_aesni",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "AESNI.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Cipher._raw_arc2",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "ARC2.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Cipher._raw_blowfish",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "blowfish.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Cipher._raw_eksblowfish",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "blowfish_eks.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Cipher._raw_cast",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "CAST.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Cipher._raw_des",
        include_dirs=["Core/", "Core/libtom/"],
        sources=[str(core_dir / "DES.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Cipher._raw_des3",
        include_dirs=["Core/", "Core/libtom/"],
        sources=[str(core_dir / "DES3.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Util._cpuid_c",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "cpuid.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Cipher._pkcs1_decode",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "pkcs1_decode.c")],
        py_limited_api=True,
    ),
    # Chaining modes
    Extension(
        "libcrypto.Cipher._raw_ecb",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "raw_ecb.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Cipher._raw_cbc",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "raw_cbc.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Cipher._raw_cfb",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "raw_cfb.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Cipher._raw_ofb",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "raw_ofb.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Cipher._raw_ctr",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "raw_ctr.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Cipher._raw_ocb",
        sources=[str(core_dir / "raw_ocb.c")],
        py_limited_api=True,
    ),
    # Stream ciphers
    Extension(
        "libcrypto.Cipher._ARC4",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "ARC4.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Cipher._Salsa20",
        include_dirs=["Core/", "Core/libtom/"],
        sources=[str(core_dir / "Salsa20.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.Cipher._chacha20",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "chacha20.c")],
        py_limited_api=True,
    ),
    # Others
    Extension(
        "libcrypto.Protocol._scrypt",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "scrypt.c")],
        py_limited_api=True,
    ),
    # Utility modules
    Extension(
        "libcrypto.Util._strxor",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "strxor.c")],
        py_limited_api=True,
    ),
    # ECC
    Extension(
        "libcrypto.PublicKey._ec_ws",
        include_dirs=[str(core_dir)],
        sources=[
            str(core_dir / "ec_ws.c"),
            str(core_dir / "mont.c"),
            str(core_dir / "p256_table.c"),
            str(core_dir / "p384_table.c"),
            str(core_dir / "p521_table.c"),
        ],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.PublicKey._curve25519",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "curve25519.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.PublicKey._curve448",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "curve448.c"), str(core_dir / "mont1.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.PublicKey._ed25519",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "ed25519.c")],
        py_limited_api=True,
    ),
    Extension(
        "libcrypto.PublicKey._ed448",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "ed448.c"), str(core_dir / "mont2.c")],
        py_limited_api=True,
    ),
    # Math
    Extension(
        "libcrypto.Math._modexp",
        include_dirs=[str(core_dir)],
        sources=[str(core_dir / "modexp.c"), str(core_dir / "mont3.c")],
        py_limited_api=True,
    ),
]
# Create the libcrypto package
if use_separate_namespace:
    # Recreate src/libcrypto from scratch, unless it is the only
    # directory available
    if os.path.isdir("src/libcrypto"):
        create_libcrypto_lib()

# Add compiler specific options.
set_compiler_options(package_root, ext_modules)

# By doing this we need to change version information in a single file
with open(os.path.join("src", package_root, "__init__.py")) as init_root:
    for line in init_root:
        if line.startswith("version_info"):
            version_tuple = eval(line.split("=")[1])

version_string = ".".join([str(x) for x in version_tuple])

# Set the minimum ABI3 version for bdist_wheel to 3.7
# unless Python is running without GIL (as there is no established way yet to
# specify multiple ABI levels)
setup_options = {}
if sys.version_info[0] > 2:
    if not sysconfig.get_config_var("Py_GIL_DISABLED"):
        setup_options["options"] = {"bdist_wheel": {"py_limited_api": "cp37"}}

setup(
    name="libcrypto",
    version=get_version(),
    description="Comprehensive cryptocurrency wallet library with BIP39/BIP32 support and optimized C extensions",
    long_description=longdesc,
    author="Mmdrza",
    author_email="pymmdrza@gmail.com",
    url="https://libcrypto.readthedocs.io",
    platforms="Posix; MacOS X; Windows",
    zip_safe=False,
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*, !=3.6.*",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: MIT License",
        "License :: Public Domain",
        "Intended Audience :: Developers",
        "Operating System :: Unix",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS :: MacOS X",
        "Topic :: Security :: Cryptography",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    license="MIT",
    packages=packages,
    package_dir={"": "src"},
    package_data=package_data,
    cmdclass={
        "build_ext": PCTBuildExt,
        "build_py": PCTBuildPy,
        "test": TestCommand,
    },
    ext_modules=ext_modules,
    **setup_options,
)
