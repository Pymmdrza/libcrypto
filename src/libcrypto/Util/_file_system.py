import os


def libcrypto_filename(dir_comps, filename):
    """Return the complete file name for the module

    dir_comps : list of string
        The list of directory names in the LibCrypto package.
        The first element must be "libcrypto".

    filename : string
        The filename (inclusing extension) in the target directory.
    """

    if dir_comps[0] != "libcrypto":
        raise ValueError("Only available for modules under 'libcrypto'")

    dir_comps = list(dir_comps[1:]) + [filename]

    util_lib, _ = os.path.split(os.path.abspath(__file__))
    root_lib = os.path.join(util_lib, "..")

    return os.path.join(root_lib, *dir_comps)
