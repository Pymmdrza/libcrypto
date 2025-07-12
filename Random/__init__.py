# -*- coding: utf-8 -*-
#
#  Random/__init__.py : PyCrypto random number generation

__all__ = ['new', 'get_random_bytes']

from os import urandom

class _UrandomRNG(object):

    def flush(self):
        """Method provided for backward compatibility only."""
        pass

    def reinit(self):
        """Method provided for backward compatibility only."""
        pass

    def close(self):
        """Method provided for backward compatibility only."""
        pass


def read(n):
    """Return a random byte string of the desired size."""
    return urandom(n)


def new(*args, **kwargs):
    """Return a file-like object that outputs cryptographically random bytes."""
    return _UrandomRNG()


def atfork():
    pass


#: Function that returns a random byte string of the desired size.
get_random_bytes = urandom

