# -*- coding: utf-8 -*-
#
#  Util/Counter.py : Fast counter for use with CTR-mode ciphers
#


def new(nbits, prefix=b"", suffix=b"", initial_value=1, little_endian=False, allow_wraparound=False):
    """Create a stateful counter block function suitable for CTR encryption modes.

    Each call to the function returns the next counter block.
    Each counter block is made up by three parts:

    +------+--------------+-------+
    |prefix| counter value|postfix|
    +------+--------------+-------+

    The counter value is incremented by 1 at each call.

    Args:
      nbits (integer):
        Length of the desired counter value, in bits. It must be a multiple of 8.
      prefix (byte string):
        The constant prefix of the counter block. By default, no prefix is
        used.
      suffix (byte string):
        The constant postfix of the counter block. By default, no suffix is
        used.
      initial_value (integer):
        The initial value of the counter. Default value is 1.
        Its length in bits must not exceed the argument ``nbits``.
      little_endian (boolean):
        If ``True``, the counter number will be encoded in little endian format.
        If ``False`` (default), in big endian format.
      allow_wraparound (boolean):
        This parameter is ignored.
        An ``OverflowError`` exception is always raised when the counter wraps
        around to zero.
    Returns:
      An object that can be passed with the :data:`counter` parameter to a CTR mode
      cipher.

    It must hold that *len(prefix) + nbits//8 + len(suffix)* matches the
    block size of the underlying block cipher.
    """

    if (nbits % 8) != 0:
        raise ValueError("'nbits' must be a multiple of 8")

    iv_bl = initial_value.bit_length()
    if iv_bl > nbits:
        raise ValueError("Initial value takes %d bits but it is longer than "
                         "the counter (%d bits)" %
                         (iv_bl, nbits))

    # Ignore wraparound
    return {"counter_len": nbits // 8,
            "prefix": prefix,
            "suffix": suffix,
            "initial_value": initial_value,
            "little_endian": little_endian
            }
