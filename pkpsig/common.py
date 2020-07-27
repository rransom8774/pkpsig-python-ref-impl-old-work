
# Authors: Robert Ransom

# This software is released to the public domain.

# To the extent permitted by law, this software is provided WITHOUT ANY
# WARRANTY WHATSOEVER.

import secrets

class DataError(Exception):
    """
    Indicates that an input was malformed.

    A real implementation should handle this exception, but for test
    purposes, it is more useful to let the caller obtain an error message.
    """
    pass

def randombytes(n):
    """
    Wrapper for secrets.token_bytes.  Present so that (a) KAT-gen code
    can patch it easily, and (b) anyone who must use this on an older
    version of Python without the secrets module can replace it by
    patching only one location.
    """
    return secrets.token_bytes(n)

def split_sequence_fields(x, fieldlengths):
    rv = []
    prev = 0
    for fieldlen in fieldlengths:
        end = prev + fieldlen
        rv.append(x[prev:end])
        prev = end
        pass
    assert(prev == len(x))
    return rv

