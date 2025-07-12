# ===================================================================
# Copyright (c) 2025, Mmdrza <pymmdrza@gmail.com>
# ====================================================================
from ..Util._raw_api import load_LibCrypto_raw_lib

_raw_cpuid_lib = load_LibCrypto_raw_lib("libcrypto.Util._cpuid_c",
                                        """
                                        int have_aes_ni(void);
                                        int have_clmul(void);
                                        """)


def have_aes_ni():
    return _raw_cpuid_lib.have_aes_ni()


def have_clmul():
    return _raw_cpuid_lib.have_clmul()
