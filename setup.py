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
package_root = "src/libcrypto"

# Handle separate namespace if needed
if use_separate_namespace:
    other_project = "pycrypto"
    other_root = "src/pycrypto"
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
    """Create a separate libcrypto namespace by copying from existing libcrypto"""
    src_dir = "src/libcrypto"
    dst_dir = "src/pycrypto"  # or whatever the separate namespace should be

    assert os.path.isdir(src_dir)

    # Remove destination directory if it exists
    try:
        shutil.rmtree(dst_dir)
    except OSError:
        pass

    # Copy the entire tree
    for root_src, dirs, files in os.walk(src_dir):
        # Calculate destination path
        root_dst = root_src.replace(src_dir, dst_dir, 1)

        # Create directories
        for dir_name in dirs:
            full_dir_name_dst = os.path.join(root_dst, dir_name)
            if not os.path.exists(full_dir_name_dst):
                os.makedirs(full_dir_name_dst)

        # Copy and modify files
        for file_name in files:
            full_file_name_src = os.path.join(root_src, file_name)
            full_file_name_dst = os.path.join(root_dst, file_name)

            print("Copying file %s to %s" % (full_file_name_src, full_file_name_dst))

            # Ensure destination directory exists
            os.makedirs(os.path.dirname(full_file_name_dst), exist_ok=True)

            # Copy file
            shutil.copy2(full_file_name_src, full_file_name_dst)

            # Modify Python files to replace namespace
            if (
                full_file_name_src.split(".")[-1] in ("py", "pyi")
                or file_name == "py.typed"
            ):
                if sys.version_info[0] > 2:
                    extra_param = {"encoding": "utf-8"}
                else:
                    extra_param = {}

                with open(full_file_name_dst, "rt", **extra_param) as fd:
                    content = fd.read().replace("libcrypto.", "pycrypto.")

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


# Define C extensions
ext_modules = [
    # Hash extensions
    Extension(
        "libcrypto.Hash._SHA256",
        sources=[str(core_dir / "SHA256.c")],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args,
    ),
    Extension(
        "libcrypto.Hash._SHA512",
        sources=[str(core_dir / "SHA512.c")],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args,
    ),
    Extension(
        "libcrypto.Hash._SHA1",
        sources=[str(core_dir / "SHA1.c")],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args,
    ),
    Extension(
        "libcrypto.Hash._SHA224",
        sources=[str(core_dir / "SHA224.c")],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args,
    ),
    Extension(
        "libcrypto.Hash._SHA384",
        sources=[str(core_dir / "SHA384.c")],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args,
    ),
    Extension(
        "libcrypto.Hash._RIPEMD160",
        sources=[str(core_dir / "RIPEMD160.c")],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args,
    ),
    Extension(
        "libcrypto.Hash._MD5",
        sources=[str(core_dir / "MD5.c")],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args,
    ),
    Extension(
        "libcrypto.Hash._MD4",
        sources=[str(core_dir / "MD4.c")],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args,
    ),
    Extension(
        "libcrypto.Hash._MD2",
        sources=[str(core_dir / "MD2.c")],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args,
    ),
    Extension(
        "libcrypto.Hash._keccak",
        sources=[str(core_dir / "keccak.c")],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args,
    ),
    Extension(
        "libcrypto.Hash._BLAKE2s",
        sources=[str(core_dir / "blake2s.c")],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args,
    ),
    Extension(
        "libcrypto.Hash._BLAKE2b",
        sources=[str(core_dir / "blake2b.c")],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args,
    ),
    # Extension(
    #     "libcrypto.Hash._poly1305",
    #     sources=[str(core_dir / "poly1305.c")],
    #     include_dirs=[str(core_dir)],
    #     extra_compile_args=compile_args,
    #     extra_link_args=link_args
    # ),
    # Cipher extensions
    Extension(
        "libcrypto.Cipher._raw_aes",
        sources=[str(core_dir / "AES.c")],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args,
    ),
    Extension(
        "libcrypto.Cipher._Salsa20",
        sources=[str(core_dir / "Salsa20.c")],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args,
    ),
    # Protocol extensions
    Extension(
        "libcrypto.Protocol._scrypt",
        sources=[str(core_dir / "scrypt.c")],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args,
    ),
    # Note: AESNI disabled due to compilation issues - can be re-enabled with proper CPU detection
    # Extension(
    #     "libcrypto.Cipher._raw_aesni",
    #     sources=[str(core_dir / "AESNI.c")],
    #     include_dirs=[str(core_dir)],
    #     extra_compile_args=compile_args,
    #     extra_link_args=link_args
    # ),
    # Utility extensions
    Extension(
        "libcrypto.Util._strxor",
        sources=[str(core_dir / "strxor.c")],
        include_dirs=[str(core_dir)],
        extra_compile_args=compile_args,
        extra_link_args=link_args,
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

# Read version from the correct location
version_string = get_version()

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
