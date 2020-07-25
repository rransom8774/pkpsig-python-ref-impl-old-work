
# Authors: Robert Ransom, NTRU Prime round 2 submitters

# The encoding and decoding functions below are based on the functions
# on pages 17 and 18 of the NTRU Prime round 2 specification.
#
# They should be revised to demonstrate more efficient techniques, but
# these near-original functions are sufficient to define the data
# format for test vector generation and interoperability testing.

# My contributions to this software are released to the public domain.

import collections

from . import common

VECTOR_ENCODE_LIMIT = 16384
VECTOR_ENCODE_OUTMOD = 256

def ceildiv(m, div):
    return (m + (div-1)) // div

def reduce_m(m, limit=VECTOR_ENCODE_LIMIT, outmod=VECTOR_ENCODE_OUTMOD):
    "m -> (m', b) where m' < limit and m >> (8*b) == m'"
    b = 0
    while m >= limit:
        b += 1
        m = ceildiv(m, outmod)
        pass
    return (m, b)

def encode(R, M):
    """
    encode(R, M) -> (S, root, root_bound)

    Almost the same as the vector encoding function in the NTRU Prime
    round 2 spec, but requires that the input vector have non-zero length,
    and returns both the "spill" of the root node and its upper bound to
    the caller separately from the byte vector.

    This change has two possible benefits.  First, when many vectors are
    packed into the same blob, storing the root nodes together in another
    vector may save some further space without adding complexity to a low-
    memory implementation which needs to pack or unpack one vector at a
    time.  Second, when there are vectors of two different types, packing
    their heads together only requires the same number of constants as
    another vector with only one upper bound; running everything through
    the encoder at once would be less orderly, and may impair optimized
    implementations.

    BUG: All values in M must be less than or equal to VECTOR_ENCODE_LIMIT.
    Ideally, this function should perform reduction and byte output before
    merging adjacent nodes, rather than after.
    """
    assert(len(M) != 0)
    assert(len(R) == len(M))
    S = []
    if len(M) == 1:
        r, m = R[0], M[0]
        return (S, r, m)
    R2, M2 = [], []
    for i in range(0, len(M)-1, 2):
        r, m = R[i] + (R[i+1] * M[i]), M[i] * M[i+1]
        while m >= VECTOR_ENCODE_LIMIT:
            S.append(r % VECTOR_ENCODE_OUTMOD)
            r = (r // VECTOR_ENCODE_OUTMOD)
            m = ceildiv(m, VECTOR_ENCODE_OUTMOD)
            pass
        R2.append(r)
        M2.append(m)
        pass
    if len(M) & 1:
        R2.append(R[-1])
        M2.append(M[-1])
        pass
    S2, root, root_bound = encode(R2, M2)
    return (S+S2, root, root_bound)

def root_bound_to_bytes(m):
    root_bytes = 0
    while m > 1:
        root_bytes += 1
        m = ceildiv(m, VECTOR_ENCODE_OUTMOD)
        pass
    return root_bytes

def encode_root(root, root_bound):
    """
    encode_root(root, root_bound) -> S

    For a given (R, M), the following should produce exactly the same result
    as the vector encoding function in the NTRU Prime round 2 spec:

       S, root, root_bound = encode(R, M)
       S += encode_root(root, root_bound)
    """
    S, r, m = [], root, root_bound
    while m > 1:
        S.append(r % VECTOR_ENCODE_OUTMOD)
        r = (r // VECTOR_ENCODE_OUTMOD)
        m = ceildiv(m, VECTOR_ENCODE_OUTMOD)
        pass
    return S

EncodingSize = collections.namedtuple('EncodingSize', ('lenS', 'root_bound', 'root_bytes'))

def size(M):
    "size(M) -> (len(S), root_bound, len(encode_root(_, root_bound)))"
    S, _, root_bound = encode([0]*len(M), M)
    root_bytes = len(encode_root(0, root_bound))
    return EncodingSize(len(S), root_bound, root_bytes)

def decode(S, M, root):
    """
    decode(S, M, root) -> R

    The inverse of encode.  See encode for description.
    """
    assert(len(M) != 0)
    if len(M) == 1:
        r = root
        assert(len(S) == 0)
        if root >= M[0]:
            raise common.DataError('Root value %d above bound %d' % (root, M[0]))
        return [root]
    k = 0
    bottom, M2 = [], []
    for i in range(0, len(M)-1, 2):
        r, t, m = 0, 1, M[i] * M[i+1]
        while m >= VECTOR_ENCODE_LIMIT:
            r, t = r + S[k]*t, t*VECTOR_ENCODE_OUTMOD
            k += 1
            m = ceildiv(m, VECTOR_ENCODE_OUTMOD)
            pass
        bottom.append((r, t))
        M2.append(m)
        pass
    if len(M) & 1:
        M2.append(M[-1])
        pass
    R2 = decode(S[k:], M2, root)
    R = []
    for i in range(0, len(M)-1, 2):
        r, t = bottom[i // 2]
        r += t*R2[i // 2]
        R.append(r % M[i])
        right = r // M[i]
        if right >= M[i+1]:
            # FIXME should try to report position; would need a tree level
            #       passed down to recursive decode calls
            raise common.DataError('Node value %d above bound %d' % (right, M[i+1]))
        R.append(right)
        pass
    if len(M) & 1:
        R.append(R2[-1])
        pass
    return R

def decode_root(S, root_bound):
    """
    decode_root(S, root_bound) -> root

    For a given (S, M), the following should produce exactly the same result
    as the vector decoding function in the NTRU Prime round 2 spec:

       lenSvec, root_bound, root_bytes = size(M)
       root = decode_root(S[lenSvec:], root_bound)
       R = decode(S[:lenSvec], M, root)
    """
    i, r, t, m = 0, 0, 1, root_bound
    while m > 1:
        if i >= len(S):
            raise common.DataError('Tried to decode root from string of wrong length')
        r, t = r + S[i]*t, t*VECTOR_ENCODE_OUTMOD
        i += 1
        m = ceildiv(m, VECTOR_ENCODE_OUTMOD)
        pass
    if i < len(S):
        raise common.DataError('Tried to decode root from string of wrong length')
    return r

