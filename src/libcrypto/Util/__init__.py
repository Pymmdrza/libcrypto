# -*- coding: utf-8 -*-
"""Miscellaneous modules

Contains useful modules that don't belong into any of the
other libcrypto.* subpackages.

========================    =============================================
Module                      Description
========================    =============================================
`libcrypto.Util.number`        Number-theoretic functions (primality testing, etc.)
`libcrypto.Util.Counter`       Fast counter functions for CTR cipher modes.
`libcrypto.Util.RFC1751`       Converts between 128-bit keys and human-readable strings of words.
`libcrypto.Util.asn1`          Minimal support for ASN.1 DER encoding
`libcrypto.Util.Padding`       Set of functions for adding and removing padding.
========================    =============================================

:undocumented: _galois, _number_new, cpuid, py3compat, _raw_api
"""

__all__ = ['RFC1751', 'number', 'strxor', 'asn1', 'Counter', 'Padding']
