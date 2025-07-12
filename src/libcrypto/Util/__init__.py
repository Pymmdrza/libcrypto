# -*- coding: utf-8 -*-
"""Miscellaneous modules

Contains useful modules that don't belong into any of the
other Crypto.* subpackages.

========================    =============================================
Module                      Description
========================    =============================================
`Crypto.Util.number`        Number-theoretic functions (primality testing, etc.)
`Crypto.Util.Counter`       Fast counter functions for CTR cipher modes.
`Crypto.Util.RFC1751`       Converts between 128-bit keys and human-readable
                            strings of words.
`Crypto.Util.asn1`          Minimal support for ASN.1 DER encoding
`Crypto.Util.Padding`       Set of functions for adding and removing padding.
========================    =============================================

:undocumented: _galois, _number_new, cpuid, py3compat, _raw_api
"""

__all__ = ['RFC1751', 'number', 'strxor', 'asn1', 'Counter', 'Padding']

