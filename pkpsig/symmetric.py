
# Authors: Robert Ransom

# This software is released to the public domain.

import struct
import hashlib

from . import params

struct_ui8 = struct.Struct('<B')
struct_ui16 = struct.Struct('<H')
struct_ui32 = struct.Struct('<I')

def pack_ui8(x):
    return struct_ui8.pack(x)
def pack_ui8_vec(x):
    return b''.join(struct_ui8.pack(el) for el in x)
def unpack_ui8_vec(x):
    return [el[0] for el in struct_ui8.iter_unpack(x)]

def pack_ui16(x):
    return struct_ui16.pack(x)
def pack_ui16_vec(x):
    return b''.join(struct_ui16.pack(el) for el in x)
def unpack_ui16_vec(x):
    return [el[0] for el in struct_ui16.iter_unpack(x)]

def pack_ui32(x):
    return struct_ui32.pack(x)
def unpack_ui32_vec(x):
    return [el[0] for el in struct_ui32.iter_unpack(x)]

def hash_init(context, prefix = None):
    hobj = hashlib.shake_256()
    hobj.update(pack_ui8(context))
    if prefix is not None:
        hobj.update(prefix)
        pass
    return hobj

def hash_expand_index_seed(hobj_, index, seed, outbytes):
    hobj = hobj_.copy()
    hobj.update(pack_ui32(index))
    hobj.update(seed)
    return hobj.digest(outbytes)

def hash_expand_index(hobj_, index, outbytes):
    return hash_expand_index_seed(hobj_, index, b'', outbytes)

def hash_expand_index_fwv_nonuniform(hobj_, index, outlen, weight):
    buf = unpack_ui32_vec(hash_expand_index(hobj_, index, outlen*4))
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

def hash_expand_index_seed_perm(hobj_, index, seed, outlen, check_uniform = False):
    buf = unpack_ui32_vec(hash_expand_index_seed(hobj_, index, seed, outlen*4))
    assert(len(buf) == outlen)
    assert(outlen <= 128) # magic number and protocol constant
    for i in range(outlen):
        buf[i] = buf[i] & 0xFFFFFF80
        buf[i] = buf[i] | i
        pass
    buf.sort()
    if check_uniform:
        for i in range(outlen - 1):
            if (buf[i] & 0xFFFFFF80) == (buf[i+1] & 0xFFFFFF80):
                return None
            pass
        pass
    for i in range(outlen):
        buf[i] = buf[i] & 0x7F
        pass
    return buf

def hash_expand_index_perm(hobj_, index, outlen, check_uniform = False):
   return hash_expand_index_seed_perm(hobj_, index, b'', outlen, check_uniform = False)

def hash_expand_index_fqvec_sorted_nodups_nonuniform(hobj_, index, outlen):
    buf = hash_expand_index_fwv(hobj_, index, params.PKP_Q, outlen)
    assert(params.PKP_Q <= 0x7FFFFFFF)
    assert(outlen <= params.PKP_Q)
    for i in range(params.PKP_Q):
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

def hash_expand_index_fqvec(hobj_, index, outlen, check_uniform = False):
    buf = unpack_ui32_vec(hash_expand_index(hobj_, index, outlen*4))
    assert(len(buf) == outlen)
    if check_uniform:
        CEILING = 0x100000000 - (0x100000000 % params.PKP_Q)
        for i in range(outlen):
            if buf[i] >= CEILING:
                return None
            pass
        pass
    for i in range(outlen):
        buf[i] = buf[i] % params.PKP_Q
        pass
    return buf

def hash_expand_suffix(hobj_, suffix, outbytes):
    hobj = hobj_.copy()
    hobj.update(suffix)
    return hobj.digest(outbytes)

def hash_digest_suffix(hobj_, suffix, outbytes):
    hobj = hobj_.copy()
    hobj.update(suffix)
    return hobj.digest(outbytes)

def fqvec_to_hash_input(vec):
    assert(params.PKP_Q <= 0xFFFF)
    for i in range(len(vec)):
        assert(vec[i] >= 0)
        assert(vec[i] <= params.PKP_Q)
        pass
    return pack_ui16_vec(vec)

def hash_digest_suffix_fqvec(hobj_, suffixvec, outbytes):
    return hash_digest_suffix(hobj_, fqvec_to_hash_input(suffixvec), outbytes)

def perm_to_hash_input(perm):
    assert(params.PKP_N <= 0xFF)
    assert(len(perm) == params.PKP_N)
    tmp = perm
    tmp.sort()
    for i in range(params.PKP_N):
        assert(tmp[i] == i)
        pass
    return pack_ui8_vec(perm)

def hash_digest_index_perm_fqvec(hobj_, index, suffixperm, suffixvec, outbytes):
    return hash_digest_suffix(hobj_, pack_ui32(index) +
                              perm_to_hash_input(suffixperm) +
                              fqvec_to_hash_input(suffixvec), outbytes)

