# -*- coding: utf-8 -*-
#
#  Util/py3compat.py : Python 3 compatibility helpers
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

"""Python 3 compatibility helpers for bytes/string handling.

This module provides helper functions for consistent handling of bytes and strings.
Requires Python 3.8+.
"""

import sys
from abc import ABC
from io import BytesIO, StringIO
from sys import maxsize as maxint


def b(s):
    """Convert a text string to bytes."""
    return s.encode("latin-1")


def bchr(s):
    """Convert an integer to a single-byte bytes object."""
    return bytes([s])


def bstr(s):
    """Convert string or int to bytes."""
    if isinstance(s, str):
        return bytes(s, "latin-1")
    else:
        return bytes(s)


def bord(s):
    """Return the integer value of a byte (identity function in Python 3)."""
    return s


def tobytes(s, encoding="latin-1"):
    """Convert various types to bytes."""
    if isinstance(s, bytes):
        return s
    elif isinstance(s, bytearray):
        return bytes(s)
    elif isinstance(s, str):
        return s.encode(encoding)
    elif isinstance(s, memoryview):
        return s.tobytes()
    else:
        return bytes([s])


def tostr(bs):
    """Convert bytes to string."""
    return bs.decode("latin-1")


def byte_string(s):
    """Check if s is a bytes object."""
    return isinstance(s, bytes)


def concat_buffers(a, b):
    """Concatenate two buffer-like objects."""
    return a + b


iter_range = range


def is_native_int(x):
    """Check if x is a native integer."""
    return isinstance(x, int)


def is_string(x):
    """Check if x is a string."""
    return isinstance(x, str)


def is_bytes(x):
    """Check if x is bytes-like."""
    return isinstance(x, (bytes, bytearray, memoryview))


FileNotFoundError = FileNotFoundError

__all__ = [
    "b",
    "bchr",
    "bstr",
    "bord",
    "tobytes",
    "tostr",
    "byte_string",
    "concat_buffers",
    "BytesIO",
    "StringIO",
    "maxint",
    "iter_range",
    "is_native_int",
    "is_string",
    "is_bytes",
    "ABC",
    "FileNotFoundError",
]


def _copy_bytes(start, end, seq):
    """Return an immutable copy of a sequence (byte string, byte array, memoryview)
    in a certain interval [start:seq]"""

    if isinstance(seq, memoryview):
        return seq[start:end].tobytes()
    elif isinstance(seq, bytearray):
        return bytes(seq[start:end])
    else:
        return seq[start:end]
