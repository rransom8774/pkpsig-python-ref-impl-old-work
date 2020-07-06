
# Authors: Robert Ransom

# This software is released to the public domain.

import struct
import hashlib
import secrets

PKP_Q = 997
PKP_N = 61
PKP_M = 28

# sizes determined by keypair security level
PKPSIG_BYTES_PUBPARAMSEED = 16
PKPSIG_BYTES_SECPERMSEED = 32
PKPSIG_BYTES_SECKEYCHECKSUM = 8
PKPSIG_BYTES_HASHSALT = 32

# sizes determined by signature security level
PKPSIG_BYTES_MESSAGEHASH = 32
PKPSIG_BYTES_COMMITHASH = 32
PKPSIG_BYTES_CHALLENGESEED = 32

# FIXME CHECK          
PKPSIG_NRUNS_LONG = 120
PKPSIG_NRUNS_SHORT = 51

VECTOR_ENCODE_LIMIT = 16384
VECTOR_ENCODE_OUTMOD = 256

# sizes derived from the above, manually for now
BYTES_PUBLICKEY = 51
BYTES_SECRETKEY = 56

class DataError(Exception):
    """
    Indicates that an input was malformed.

    A real implementation should handle this exception, but for test
    purposes, it is more useful to let the caller obtain an error message.
    """
    pass

def vectcoder_ceildiv(m, div):
    return (m + (div-1)) // div

def vector_encode(R, M):
    """
    vector_encode(R, M) -> (S, root, root_bound)
    
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
            m = vectcoder_ceildiv(m, VECTOR_ENCODE_OUTMOD)
            pass
        R2.append(r)
        M2.append(m)
        pass
    if len(M) & 1:
        R2.append(R[-1])
        M2.append(M[-1])
        pass
    S2, root, root_bound = vector_encode(R2, M2)
    return (S+S2, root, root_bound)

def vector_decode(S, M, root):
    """
    vector_decode(S, M, root) -> R

    The inverse of vector_encode.  See vector_encode for description.
    """
    assert(len(M) != 0)
    if len(M) == 1:
        r = root
        assert(len(S) == 0)
        if root >= M[0]:
            raise DataError('Root value %d above bound %d' % (root, M[0]))
        return [root]
    k = 0
    bottom, M2 = [], []
    for i in range(0, len(M)-1, 2):
        r, t, m = 0, 1, M[i] * M[i+1]
        while m >= VECTOR_ENCODE_LIMIT:
            r, t = r + S[k]*t, t*VECTOR_ENCODE_OUTMOD
            k += 1
            m = vectcoder_ceildiv(m, VECTOR_ENCODE_OUTMOD)
            pass
        bottom.append((r, t))
        M2.append(m)
        pass
    if len(M) & 1:
        M2.append(M[-1])
        pass
    R2 = vector_decode(S[k:], M2, root)
    R = []
    for i in range(0, len(M)-1, 2):
        r, t = bottom[i // 2]
        r += t*R2[i // 2]
        R.append(r % M[i])
        right = r // M[i]
        if right >= M[i+1]:
            # FIXME should try to report position; would need a tree level
            #       passed down to recursive vector_decode calls
            raise DataError('Node value %d above bound %d' % (right, M[i+1]))
        R.append(right)
        pass
    if len(M) & 1:
        R.append(R2[-1])
        pass
    return R

struct_ui32 = struct.Struct('<i')

def pack_ui32(x):
    return struct_ui32.pack(x)

def unpack_ui32_vec(x):
    return [el[0] for el in struct_ui32.iter_unpack(x)]

HASHCTX_PUBPARAMS = 0
HASHCTX_SECPERM = 1
HASHCTX_GENSALT = 2
HASHCTX_MESSAGEHASH = 3
HASHCTX_EXPANDBLINDSEED = 4
HASHCTX_COMMITMENT = 5
HASHCTX_CHALLENGE1 = 6
HASHCTX_CHALLENGE2 = 7

HASHIDX_PUBPARAMS_V = 0

def sym_hash_init(context, prefix = None):
    hobj = hashlib.shake_256()
    hobj.update(pack_ui32(context))
    if prefix is not None:
        hobj.update(prefix)
        pass
    return hobj

def sym_hash_expand_index(hobj_, index, outbytes):
    hobj = hobj_.copy()
    hobj.update(pack_ui32(index))
    return hobj.digest(outbytes)

def sym_hash_expand_index_fwv(hobj_, index, outlen, weight):
    buf = unpack_ui32_vec(sym_hash_expand_index(hobj_, index, outlen*4))
    assert(len(buf) == outlen)
    for i in range(outlen):
        buf[i] = buf[i] & 0xFFFFFFFE
        if i < weight:
            buf[i] = buf[i] | 1
            pass
        pass
    buf.sort()
    for i in range(outlen):
        buf[i] = buf[i] & 1
        pass
    return buf

def sym_hash_expand_index_fqvec_sorted_nodups(hobj_, index, outlen):
    buf = sym_hash_expand_index_fwv(hobj_, index, PKP_Q, outlen)
    assert(PKP_Q <= 0x7FFFFFFF)
    assert(outlen <= PKP_Q)
    for i in range(PKP_Q):
        old = buf[i]
        new_opt = (i & -buf[i]) | ((buf[i] - 1) & 0x7FFFFFFF)
        if old == 1:
            new = i
            pass
        elif old == 0:
            new = 0x7FFFFFFF
            pass
        else:
            raise Exception('internal error pUq6Qfm1_Kg: %d %r' % (i, buf[i]))
        assert(new == new_opt)
        buf[i] = new
        pass
    buf.sort()
    return buf[:outlen]

def sym_hash_expand_index_fqvec_nonuniform(hobj_, index, outlen):
    buf = unpack_ui32_vec(sym_hash_expand_index(hobj_, index, outlen*4))
    assert(len(buf) == outlen)
    for i in range(outlen):
        buf[i] = buf[i] % PKP_Q
        pass
    return buf

def sym_hash_expand_suffix(hobj_, suffix, outbytes):
    hobj = hobj_.copy()
    hobj.update(suffix)
    return hobj.digest(outbytes)

def sym_hash_digest_suffix(hobj_, suffix, outbytes):
    hobj = hobj_.copy()
    hobj.update(suffix)
    return hobj.digest(outbytes)

class PublicMatrix(object):
    """
    A simple wrapper for the non-identity part of a column-major m*n matrix
    in reduced row-echelon form mod q.
    """
    __slots__ = ('cols',)
    def __init__(self):
        self.cols = [None for i in range(PKP_N - PKP_M)]
        pass
    def __getitem__(self, i):
        assert(i >= PKP_M)
        assert(i < PKP_N)
        return self.cols[i - PKP_M]
    def __setitem__(self, i, v):
        assert(i >= PKP_M)
        assert(i < PKP_N)
        self.cols[i - PKP_M] = v
        pass
    pass

class PublicParams(object):
    __slots__ = ('Aprime', 'v')
    def expand_seed(self, seed):
        hobj = sym_hash_init(HASHCTX_PUBPARAMS, seed)
        # Generate v as a vector of length n mod q without duplicates
        self.v = sym_hash_expand_index_fqvec_sorted_nodups(hobj, HASHIDX_PUBPARAMS_V, PKP_N)
        # Generate A'
        self.Aprime = PublicMatrix()
        for i in range(PKP_M, PKP_N, 1):
            self.Aprime[i] = sym_hash_expand_index_fqvec_nonuniform(hobj, i, PKP_M)
            pass
        return self
    pass

class PublicKey(PublicParams):
    __slots__ = ('w',)
    def unpack(self, keyblob):
        self.expand_seed(keyblob[0:PKPSIG_BYTES_PUBPARAMSEED])
        
        
        return self
    pass

class SecretKey(PublicKey):
    __slots__ = ('pi_inv',)
    pass




